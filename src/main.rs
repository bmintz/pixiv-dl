extern crate failure;
extern crate image;
#[macro_use]
extern crate lazy_static;
extern crate rayon;
extern crate regex;
extern crate reqwest;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate toml;
extern crate zip;

mod png;

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, BufRead, ErrorKind::NotFound, Read, Write},
    path::Path,
    thread, time,
};

use image::GenericImageView;
use rayon::prelude::*;
use regex::Regex;
use reqwest::{
    header::{self, HeaderMap, HeaderValue},
    Client,
};

macro_rules! input {
    ($x:expr) => {{
        print!($x);
        ::std::io::stdout().flush()
    }};
}

lazy_static! {
    static ref CHARSET: HashSet<char> = {
        let mut charset = HashSet::new();
        charset.insert('<');
        charset.insert('>');
        charset.insert(':');
        charset.insert('"');
        charset.insert('/');
        charset.insert('\\');
        charset.insert('|');
        charset.insert('?');
        charset.insert('*');
        charset
    };
}

lazy_static! {
    static ref IEND: png::Chunk = png::Chunk::new(png::IEND);
}

static URL_BASE: &str = "https://app-api.pixiv.net/v1/";
static AUTH_URL: &str = "https://oauth.secure.pixiv.net/auth/token";

struct Downloader {
    client: Client,
    headers: HeaderMap,
    delay: time::Duration,
}

struct IllustIterator<'a> {
    downloader: &'a Downloader,
    user_id: String,
    offset: usize,
    illusts: Vec<serde_json::Value>,
    typ: String,
}

#[derive(Deserialize, Debug)]
struct LoginOuterResponse {
    response: LoginResponse,
}

#[derive(Deserialize, Debug)]
struct LoginResponse {
    access_token: String,
}

enum OnDuplicate {
    Save,
    Skip,
    Quit,
}

impl<'a> IllustIterator<'a> {
    fn new(downloader: &'a Downloader, user_id: String, typ: &str) -> Self {
        Self {
            downloader: downloader,
            user_id: user_id,
            offset: 0,
            illusts: Vec::new(),
            typ: typ.into(),
        }
    }
}

impl<'a> Iterator for IllustIterator<'a> {
    type Item = serde_json::Value;

    fn next(&mut self) -> Option<Self::Item> {
        if self.illusts.is_empty() {
            match self
                .downloader
                .user_illusts(&self.user_id, self.offset, &self.typ)
            {
                Ok(mut resp) => match resp["illusts"].as_array_mut() {
                    Some(illusts) => {
                        self.illusts.append(illusts);
                        self.offset += 30;
                    }
                    None => {}
                },
                Err(e) => println!("{:#?}", e),
            }
        }
        self.illusts.pop()
    }
}

impl Downloader {
    fn new(delay: u16) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, sdch"),
        );
        Self {
            client: Client::new(),
            headers: headers,
            delay: time::Duration::from_secs(delay.into()),
        }
    }

    fn login(&mut self, username: &str, password: &str) -> ::reqwest::Result<bool> {
        let mut form = HashMap::new();
        form.insert("get_secure_url", "1");
        form.insert("client_id", "MOBrBDS8blbauoSck0ZfDbtuzpyT");
        form.insert("client_secret", "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj");
        form.insert("grant_type", "password");
        form.insert("username", username);
        form.insert("password", password);
        let mut resp = self
            .client
            .post(AUTH_URL)
            .headers(self.headers.clone())
            .form(&form)
            .send()?;
        let outer: LoginOuterResponse = match resp.json() {
            Ok(r) => r,
            Err(_) => {
                log("Failed to log in!");
                println!("{:#?}", resp.json::<serde_json::Value>());
                return Ok(false);
            }
        };
        self.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", outer.response.access_token)).unwrap(),
        );
        Ok(true)
    }

    fn get(
        &self,
        suffix: &str,
        params: &HashMap<&str, String>,
    ) -> ::reqwest::Result<::reqwest::Response> {
        self.client
            .get(&format!("{}{}", URL_BASE, suffix))
            .headers(self.headers.clone())
            .query(&params)
            .send()
    }

    fn get_with_referer(&self, url: &str, referer: &str) -> ::reqwest::Result<::reqwest::Response> {
        let mut headers = self.headers.clone();
        headers.insert(header::REFERER, HeaderValue::from_str(referer).unwrap());
        self.client.get(url).headers(headers).send()
    }

    fn ugoira_metadata(&self, illust_id: &str) -> reqwest::Result<serde_json::Value> {
        let suffix = "ugoira/metadata";
        let mut params = HashMap::new();
        params.insert("illust_id", illust_id.into());
        self.get(suffix, &params)?.json()
    }

    fn user_illusts(
        &self,
        user_id: &str,
        offset: usize,
        typ: &str,
    ) -> reqwest::Result<serde_json::Value> {
        let suffix = "user/illusts";
        let mut params = HashMap::new();
        params.insert("user_id", user_id.into());
        params.insert("filter", "for_ios".into());
        params.insert("type", typ.into());
        params.insert("offset", offset.to_string());
        self.get(suffix, &params)?.json()
    }

    fn user_detail(&self, user_id: &str) -> reqwest::Result<serde_json::Value> {
        let suffix = "user/detail";
        let mut params = HashMap::new();
        params.insert("user_id", user_id.into());

        self.get(suffix, &params)?.json()
    }

    fn download_user(&self, user_id: &str, on_dup: &OnDuplicate) -> Result<(), failure::Error> {
        let detail = self.user_detail(user_id)?;
        let mut user_folder = String::new();
        let username: String;
        match detail.get("user") {
            Some(user) => {
                let raw_name = user["name"].as_str().unwrap();

                let mut temp = String::with_capacity(raw_name.len());
                for ch in raw_name.chars() {
                    if !CHARSET.contains(&ch) {
                        temp.push(ch)
                    }
                }

                username = temp;

                match fs::read_dir(Path::new(".")) {
                    Ok(dir) => {
                        for path in dir {
                            let dirname: String = path?.path().to_string_lossy().into();
                            if dirname.contains(user_id) {
                                if !dirname.contains(&username) {
                                    match dirname
                                        .chars()
                                        .enumerate()
                                        .filter(|(_, ch)| !['+', '=', '-', '_'].contains(ch))
                                        .map(|(idx, _)| idx)
                                        .next()
                                    {
                                        Some(idx) => {
                                            let new_dirname = format!(
                                                "{}{}][{}",
                                                &dirname[..idx],
                                                username,
                                                &dirname[idx..]
                                            );
                                            match fs::rename(&dirname, &new_dirname) {
                                                Ok(()) => user_folder = new_dirname,
                                                Err(_) => {
                                                    user_folder = dirname;
                                                    log(format!(
                                                        "Failed to add name {} to {}.",
                                                        &username, &user_folder
                                                    ));
                                                }
                                            }
                                        }
                                        None => {}
                                    }
                                } else {
                                    user_folder = dirname;
                                }
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log("Failed to read directory!");
                        println!("{:#?}", e);
                    }
                }
                if user_folder.is_empty() {
                    user_folder = format!("__{}({})__", username, user_id);
                    fs::create_dir(&user_folder)?;
                }
                let illust_iterator = IllustIterator::new(self, user_id.into(), "illust")
                    .chain(IllustIterator::new(self, user_id.into(), "manga"));
                for illust in illust_iterator {
                    let illust_id = &illust["id"].as_u64().unwrap().to_string();
                    if illust["type"] == "ugoira" {
                        match self.download_ugoira(illust_id, &user_folder, on_dup) {
                            Ok(Some(path)) => {
                                log(format!("Downloaded {}", path));
                                thread::sleep(self.delay);
                            }
                            Ok(None) => match on_dup {
                                OnDuplicate::Quit => return Ok(()),
                                OnDuplicate::Skip => {}
                                OnDuplicate::Save => unreachable!(),
                            },
                            Err(e) => {
                                log(format!("Failed to download illust {}", illust_id));
                                println!("{:#?}", e);
                            }
                        }
                    } else {
                        let pages = illust["meta_pages"].as_array().unwrap();
                        if !pages.is_empty() {
                            for page in pages.iter() {
                                let img_url = &page["image_urls"]["original"].as_str().unwrap();
                                let referer = format!("https://www.pixiv.net/member_illust.php?mode=manga&illust_id={}", illust_id);
                                match self.download_image(img_url, &user_folder, &referer, on_dup) {
                                    Ok(Some(path)) => {
                                        log(format!("Downloaded {}", path));
                                        thread::sleep(self.delay)
                                    }
                                    Ok(None) => match on_dup {
                                        OnDuplicate::Quit => return Ok(()),
                                        OnDuplicate::Skip => break,
                                        OnDuplicate::Save => unreachable!(),
                                    },
                                    Err(e) => {
                                        log(format!("Failed to download illust {}", illust_id));
                                        println!("{:#?}", e);
                                    }
                                }
                            }
                        } else {
                            let img_url = &illust["meta_single_page"]["original_image_url"]
                                .as_str()
                                .unwrap();
                            let referer = format!(
                                "https://www.pixiv.net/member_illust.php?mode=medium&illust_id={}",
                                illust_id
                            );
                            match self.download_image(img_url, &user_folder, &referer, &on_dup) {
                                Ok(Some(path)) => {
                                    log(format!("Downloaded {}", path));
                                    thread::sleep(self.delay);
                                }
                                Ok(None) => match on_dup {
                                    OnDuplicate::Quit => return Ok(()),
                                    OnDuplicate::Skip => {}
                                    OnDuplicate::Save => unreachable!(),
                                },
                                Err(e) => {
                                    log(format!("Failed to download illust {}", illust_id));
                                    println!("{:#?}", e);
                                }
                            }
                        }
                    }
                }
            }
            None => {
                log(format!("User with id {} is invalid", user_id));
            }
        }
        Ok(())
    }

    fn download_image(
        &self,
        url: &str,
        path: &str,
        referer: &str,
        on_dup: &OnDuplicate,
    ) -> Result<Option<String>, failure::Error> {
        let img_path = Path::new(path).join(&url[url.rfind('/').unwrap() + 1..]);
        if Path::new(&img_path).exists() {
            match on_dup {
                OnDuplicate::Save => {}
                _ => return Ok(None),
            }
        }
        let mut resp = self.get_with_referer(url, referer)?;
        let mut img_file = fs::File::create(&img_path)?;
        resp.copy_to(&mut img_file)?;
        Ok(Some(img_path.to_string_lossy().into_owned()))
    }

    fn download_ugoira(
        &self,
        illust_id: &str,
        path: &str,
        on_dup: &OnDuplicate,
    ) -> Result<Option<String>, failure::Error> {
        let img_path = Path::new(path).join(format!("{}.png", illust_id));
        if img_path.exists() {
            match on_dup {
                OnDuplicate::Save => {}
                _ => return Ok(None),
            }
        }

        let illust_url = &format!(
            "https://www.pixiv.net/member_illust.php?mode=medium&illust_id={}",
            illust_id
        );

        let metadata = &self.ugoira_metadata(illust_id)?["ugoira_metadata"];

        let zip_url = &metadata["zip_urls"]["medium"].as_str().unwrap();
        let full_zip_url = &format!(
            "{}/{}_ugoira1920x1080.zip",
            &zip_url[..zip_url.rfind("/").unwrap()],
            illust_id
        );

        let mut resp = self.get_with_referer(full_zip_url, illust_url)?;
        let mut buf = Vec::new();
        resp.read_to_end(&mut buf)?;

        let reader = io::Cursor::new(buf.as_slice());
        let mut archive = zip::ZipArchive::new(reader)?;

        let first_frame = image::load_from_memory(
            archive
                .by_index(0)
                .unwrap()
                .bytes()
                .filter_map(|b| b.ok())
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

        let (width, height) = first_frame.dimensions();

        /*let mut pixels = Vec::new();
        let frames: Vec<Vec<u8>> = (0..archive.len())
            .map(|idx| {
                let mut file = archive.by_index(idx).unwrap();
                file.read_to_end(&mut pixels).unwrap();

                let image = image::load_from_memory(pixels.as_slice())
                    .unwrap()
                    .to_rgba()
                    .into_raw();
                pixels.clear();
                image
            }).collect();*/

        let mut png_image = png::Image::new(&img_path)?;

        let mut ihdr = png::Chunk::new(png::IHDR);
        ihdr.write_u32(width);
        ihdr.write_u32(height);
        ihdr.write(&[8, 2, 0, 0, 0]); // bit depth, truecolor, then header fields
        png_image.write(&ihdr)?;

        /*        for frame in frames.iter() {
            //            encoder.write_frame(frame)?;
        }*/

        let mut idat = png::Chunk::new(png::IDAT);
        idat.write(first_frame.to_rgb().into_raw().as_slice());
        png_image.write(&idat)?;

        png_image.write(&IEND)?;
        Ok(Some(img_path.to_string_lossy().into_owned()))
    }
}

fn log<S>(message: S)
where
    S: std::fmt::Display,
{
    println!("{} {}", chrono::Local::now().format("%H:%M:%S"), message);
}

fn main() -> Result<(), failure::Error> {
    let mut input = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let (username, password): (String, String) = match fs::File::open("pixiv.toml") {
        Ok(mut file) => {
            file.read_to_string(&mut input)?;
            let value: toml::Value = input.parse()?;
            input.clear();
            let (username, password) = (value["username"].as_str(), value["password"].as_str());
            match (username, password) {
                (Some(u), Some(p)) => (u.into(), p.into()),
                _ => {
                    log("Bad TOML file. Correct or delete it.");
                    return Ok(());
                }
            }
        }
        Err(e) => match e.kind() {
            NotFound => {
                let mut username = String::new();
                let mut password = String::new();
                log("pixiv.toml not found!");
                input!("Enter username: ")?;
                handle.read_line(&mut username)?;
                input!("Enter password: ")?;
                handle.read_line(&mut password)?;
                match fs::File::create("pixiv.toml") {
                    Ok(mut file) => {
                        write!(
                            file,
                            "username = \"{}\"\npassword = \"{}\"\n",
                            &username.trim(),
                            &password.trim()
                        )?;
                    }
                    Err(e) => {
                        log("Failed to save to file");
                        println!("{:#?}", e);
                    }
                }
                (username, password)
            }
            _ => panic!("{:#?}", e),
        },
    };

    let delay: u16 = loop {
        break 0;
        input!("Enter seconds to delay between image downloads: ")?;
        handle.read_line(&mut input)?;
        match input.trim().parse() {
            Ok(num) => break num,
            Err(_) => input.clear(),
        }
    };

    let mut dl = Downloader::new(delay);
    match dl.login(&username, &password) {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => {
            log("Failed to log in!");
            println!("{:#?}", e);
            return Ok(());
        }
    };

    dl.download_ugoira("44298467", ".", &OnDuplicate::Save)?;
    return Ok(());

    loop {
        input!("What would you like to do?\n1: Check for updates\n2: Download a new artist\n3: Exit\n> ")?;
        input.clear();
        handle.read_line(&mut input)?;
        match input.trim().parse() {
            Ok(1) => {
                let on_dup = loop {
                    input!("1: Skip old works\n2: Quit on old works\n> ")?;
                    input.clear();
                    handle.read_line(&mut input)?;
                    match input.trim().parse() {
                        Ok(1) => break OnDuplicate::Skip,
                        Ok(2) => break OnDuplicate::Quit,
                        _ => {}
                    }
                };

                let mut uids: Vec<String> = Vec::new();
                let re = Regex::new(r"\((\d+)\)[-+=_]{0,2}$").unwrap();
                match fs::read_dir(Path::new(".")) {
                    Ok(dir) => {
                        for path in dir {
                            if let Some(m) = re.captures(path?.path().to_string_lossy().as_ref()) {
                                uids.push(m.get(1).unwrap().as_str().into());
                            }
                        }
                    }
                    Err(e) => {
                        log("Could not read directory!");
                        println!("{:#?}", e);
                        return Ok(());
                    }
                }
                uids.into_par_iter()
                    .for_each(|uid| match dl.download_user(&uid, &on_dup) {
                        Ok(()) => {}
                        Err(e) => {
                            log(format!("Failed to download user {}", uid));
                            println!("{:#?}", e);
                        }
                    });
            }
            Ok(2) => {
                let on_dup = loop {
                    input!("1: Skip existing works\n2: Overwrite existing works\n> ")?;
                    input.clear();
                    handle.read_line(&mut input)?;
                    match input.trim().parse() {
                        Ok(1) => break OnDuplicate::Skip,
                        Ok(2) => break OnDuplicate::Save,
                        _ => {}
                    }
                };

                input!("Enter user IDs separated by spaces: ")?;
                input.clear();
                handle.read_line(&mut input)?;
                input.trim().par_split_whitespace().for_each(|uid| {
                    match dl.download_user(uid, &on_dup) {
                        Ok(()) => {}
                        Err(e) => {
                            log(format!("Failed to download user {}", uid));
                            println!("{:#?}", e);
                        }
                    }
                });
            }
            Ok(3) => {
                println!("Goodbye!");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
