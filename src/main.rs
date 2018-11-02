extern crate color_quant;
extern crate gif;
extern crate image;
extern crate rayon;
extern crate regex;
extern crate reqwest;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate toml;
extern crate zip;

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, BufRead, ErrorKind::NotFound, Read, Write},
    path::Path,
    thread,
};

use gif::SetParameter;
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

static URL_BASE: &str = "https://app-api.pixiv.net/v1/";
static AUTH_URL: &str = "https://oauth.secure.pixiv.net/auth/token";

struct Downloader {
    client: Client,
    headers: HeaderMap,
    delay: std::time::Duration,
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
            let mut resp = self
                .downloader
                .user_illusts(&self.user_id, self.offset, &self.typ)
                .unwrap();
            self.illusts.append(resp["illusts"].as_array_mut().unwrap());
            self.offset += 30;
        }
        self.illusts.pop()
    }
}

impl Downloader {
    fn new(delay: u16) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("App-OS", HeaderValue::from_static("ios"));
        headers.insert("App-OS-Version", HeaderValue::from_static("10.3.1"));
        headers.insert("App-Version", HeaderValue::from_static("6.7.1"));
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("PixivIOSApp/6.7.1 (ios 10.3.1; iPhone8,1)"),
        );
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, sdch"),
        );
        Self {
            client: Client::new(),
            headers: headers,
            delay: std::time::Duration::from_secs(delay.into()),
        }
    }

    fn login(&mut self, username: &str, password: &str) -> ::reqwest::Result<()> {
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
        let outer: LoginOuterResponse = resp.json()?;
        self.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", outer.response.access_token.as_str()))
                .unwrap(),
        );
        Ok(())
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

    fn download_user(&self, user_id: &str, on_dup: &OnDuplicate) {
        let detail = self.user_detail(user_id).unwrap();
        let mut user_folder = String::new();
        let username: String;
        match detail.get("user") {
            Some(user) => {
                let pwd = Path::new(".");
                let raw_name = user["name"].as_str().unwrap();

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

                let mut temp = String::with_capacity(raw_name.len());
                for ch in raw_name.chars() {
                    if !charset.contains(&ch) {
                        temp.push(ch)
                    }
                }

                username = temp;

                for path in fs::read_dir(pwd).unwrap() {
                    let dirname: String = path.unwrap().path().to_string_lossy().into();
                    if dirname.contains(user_id) {
                        if !dirname.contains(&username) {
                            let (idx, _) = dirname
                                .chars()
                                .enumerate()
                                .filter(|(_, ch)| !['+', '=', '-', '_'].contains(ch))
                                .next()
                                .unwrap();
                            let new_dirname =
                                format!("{}{}][{}", &dirname[..idx], username, &dirname[idx..]);
                            match fs::rename(&dirname, &new_dirname) {
                                Ok(()) => user_folder = new_dirname,
                                Err(_) => {
                                    user_folder = dirname;
                                    log(&format!(
                                        "Failed to add name {} to {}.",
                                        &username, &user_folder
                                    ));
                                }
                            }
                        } else {
                            user_folder = dirname;
                        }
                        break;
                    }
                }
                if user_folder.is_empty() {
                    user_folder = format!("__{}({})__", username, user_id);
                    fs::create_dir(&user_folder).unwrap();
                }
                let illust_iterator = IllustIterator::new(self, user_id.into(), "illust")
                    .chain(IllustIterator::new(self, user_id.into(), "manga"));
                for illust in illust_iterator {
                    let illust_id = &illust["id"].as_u64().unwrap().to_string();
                    if illust["type"] == "ugoira" {
                        match self.download_ugoira(&illust_id, &user_folder, on_dup) {
                            Ok(true) => {
                                log(&format!("Downloaded {} (gif)", illust_id));
                                thread::sleep(self.delay);
                            }
                            Ok(false) => {}
                            Err(()) => return,
                        }
                    } else {
                        let pages = illust["meta_pages"].as_array().unwrap();
                        if !pages.is_empty() {
                            for (idx, page) in pages.iter().enumerate() {
                                let img_url = page["image_urls"]["original"].as_str().unwrap();
                                let referer = format!("https://www.pixiv.net/member_illust.php?mode=manga&illust_id={}", illust_id);
                                match self.download_image(&img_url, &user_folder, &referer, on_dup)
                                {
                                    Ok(true) => {
                                        log(&format!(
                                            "Downloaded {}{}{} page {}",
                                            user_folder,
                                            std::path::MAIN_SEPARATOR,
                                            illust_id,
                                            idx + 1
                                        ));
                                        thread::sleep(self.delay)
                                    }
                                    Ok(false) => break,
                                    Err(()) => return,
                                }
                            }
                        } else {
                            let img_url = illust["meta_single_page"]["original_image_url"]
                                .as_str()
                                .unwrap();
                            let referer = format!(
                                "https://www.pixiv.net/member_illust.php?mode=medium&illust_id={}",
                                illust_id
                            );
                            match self.download_image(&img_url, &user_folder, &referer, &on_dup) {
                                Ok(true) => {
                                    log(&format!(
                                        "Downloaded {}{}{}",
                                        user_folder,
                                        std::path::MAIN_SEPARATOR,
                                        illust_id
                                    ));
                                    thread::sleep(self.delay);
                                }
                                Ok(false) => {}
                                Err(()) => return,
                            }
                        }
                    }
                }
            }
            None => {
                log(&format!("User with id {} is invalid", user_id));
            }
        }
    }

    fn download_image(
        &self,
        url: &str,
        path: &str,
        referer: &str,
        on_dup: &OnDuplicate,
    ) -> Result<bool, ()> {
        let img_path = &format!("{}{}", path, &url[url.rfind('/').unwrap()..]);
        if Path::new(img_path).exists() {
            match on_dup {
                OnDuplicate::Skip => return Ok(false),
                OnDuplicate::Quit => return Err(()),
                OnDuplicate::Save => {}
            }
        }
        let mut resp = self.get_with_referer(url, referer).unwrap();
        let mut img_file = fs::File::create(img_path).unwrap();
        resp.copy_to(&mut img_file).unwrap();
        Ok(true)
    }

    fn download_ugoira(
        &self,
        illust_id: &str,
        path: &str,
        on_dup: &OnDuplicate,
    ) -> Result<bool, ()> {
        let img_path = &format!("{}{}{}.gif", path, std::path::MAIN_SEPARATOR, illust_id);

        if Path::new(img_path).exists() {
            match on_dup {
                OnDuplicate::Skip => return Ok(false),
                OnDuplicate::Quit => return Err(()),
                OnDuplicate::Save => {}
            }
        }

        let illust_url = &format!(
            "https://www.pixiv.net/member_illust.php?mode=medium&illust_id={}",
            illust_id
        );

        let metadata = &self.ugoira_metadata(illust_id).unwrap()["ugoira_metadata"];

        let zip_url = &metadata["zip_urls"]["medium"].as_str().unwrap();
        let full_zip_url = &format!(
            "{}/{}_ugoira1920x1080.zip",
            &zip_url[..zip_url.rfind("/").unwrap()],
            illust_id
        );

        let mut resp = self.get_with_referer(full_zip_url, illust_url).unwrap();
        let mut buf = Vec::new();
        resp.read_to_end(&mut buf).unwrap();

        let reader = io::Cursor::new(buf.as_slice());
        let mut archive = zip::ZipArchive::new(reader).unwrap();

        let first_frame = image::load_from_memory(
            archive
                .by_index(0)
                .unwrap()
                .bytes()
                .filter_map(|b| b.ok())
                .collect::<Vec<_>>()
                .as_slice(),
        ).unwrap();

        let dimensions = first_frame.dimensions();
        let width = dimensions.0 as u16;
        let height = dimensions.1 as u16;

        let mut img_file = fs::File::create(img_path).unwrap();
        let mut encoder = gif::Encoder::new(&mut img_file, width, height, &[]).unwrap();
        encoder.set(gif::Repeat::Infinite).unwrap();

        let images: Vec<Vec<u8>> = (0..archive.len())
            .map(|idx| {
                let mut file = archive.by_index(idx).unwrap();
                let mut pixels = Vec::new();
                file.read_to_end(&mut pixels).unwrap();

                image::load_from_memory(pixels.as_slice())
                    .unwrap()
                    .to_rgba()
                    .into_raw()
            }).collect();

        let frames: Vec<gif::Frame> = images
            .into_par_iter()
            .enumerate()
            .map(|(idx, mut image)| {
                let mut frame = gif::Frame::from_rgba(width, height, image.as_mut_slice());
                frame.delay = (metadata["frames"][idx]["delay"].as_u64().unwrap() / 1000) as u16;
                frame
            }).collect();

        frames
            .iter()
            .for_each(|frame| encoder.write_frame(frame).unwrap());
        Ok(true)
    }
}

fn log(message: &str) {
    println!("{} {}", chrono::Local::now().format("%H:%M:%S"), message);
}

fn main() -> io::Result<()> {
    let mut input = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let (username, password): (String, String) = match fs::File::open("pixiv.toml") {
        Ok(mut file) => {
            file.read_to_string(&mut input)?;
            let value: toml::Value = input.parse().unwrap();
            input.clear();
            (
                value["username"].as_str().unwrap().into(),
                value["password"].as_str().unwrap().into(),
            )
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
                            r#"username = "{}"\npassword = "{}"\n"#,
                            &username, &password
                        )?;
                    }
                    Err(e) => log(&format!("Failed to save to file\n{:#?}", e)),
                }
                (username, password)
            }
            _ => panic!("{:#?}", e),
        },
    };

    let delay: u16 = loop {
        input!("Enter seconds to delay between image downloads: ")?;
        handle.read_line(&mut input)?;
        match input.trim().parse() {
            Ok(num) => break num,
            Err(_) => input.clear(),
        }
    };

    let mut dl = Downloader::new(delay);
    dl.login(&username, &password).unwrap();
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
                let pwd = Path::new(".");
                for path in fs::read_dir(pwd).unwrap() {
                    if let Some(m) = re.captures(path?.path().to_string_lossy().as_ref()) {
                        uids.push(m.get(1).unwrap().as_str().into());
                    }
                }
                uids.into_par_iter()
                    .for_each(|uid| dl.download_user(&uid, &on_dup));
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
                input
                    .trim()
                    .par_split_whitespace()
                    .for_each(|uid| dl.download_user(uid, &on_dup));
            }
            Ok(3) => {
                log("Goodbye!");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
