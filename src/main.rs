use std::{
        fs, 
        io::{
            BufRead,
            Write,
            prelude::*
    },
    num::ParseIntError,
    path::{Path, PathBuf},
    str::FromStr
};
use walkdir::WalkDir;

struct FileCheckResult {
    mismatching_extensions: Vec<PathBuf>,
    failed_to_open: Vec<PathBuf>
}

impl FileCheckResult {
    fn new() -> Self {
        FileCheckResult {
            mismatching_extensions: Vec::new(),
            failed_to_open: Vec::new()
        }
    }
    fn write_to_file(&self, p: &Path) -> Result<(), &'static str> {
        let gap = "\n----------\n";
        let mut f = fs::File::create(p).expect("Unable to create file");
        write!(f, "Mismatching extensions\n").unwrap();
        for pb in &self.mismatching_extensions{
            write!(f, "{}\n", pb.display()).expect("Failed to write path to output file");
        }
        if self.failed_to_open.len() > 0 {
            write!(f, "{}", gap).unwrap();
            write!(f, "Failed to open").unwrap();
            for pb in &self.failed_to_open{
                write!(f, "{}\n", pb.display()).expect("Failed to write path to output file");
            }
        }
        Ok(())
    }
}

struct Signature {
    magic_number: Vec<u8>,
    name: Vec<String>
}

impl FromStr for Signature {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = s.split(":").collect();
        let magic_number: Vec<u8> = split[0].split_whitespace().map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
        let name: Vec<String> = split[1].split(",").map(|s| s.to_owned()).collect();
        Ok(Signature {
            magic_number,
            name
        })
    }
}

impl Signature {
    fn new_from_file(filename: &str) -> Vec<Signature> {
        let mut contents: Vec<Signature> = Vec::new();
        let file = fs::File::open(filename).expect("Failed to open input file");
        let lines = std::io::BufReader::new(file).lines();
        for line in lines {
            if let Ok(line) = line {
                contents.push(line.parse().expect("Failed to parse signature line"));
            }
        }
        contents
    }
}

fn magic_number_match(magic_number: &Vec<u8>, file_buf: &[u8]) -> bool {
    for (index, b) in magic_number.iter().enumerate() {
        if file_buf[index] != *b {
            return false;
        }
    }
    true
}

fn is_file_mismatched(signatures: &Vec<Signature>, buf: &[u8], ext: &str) -> bool {
    for signature in signatures {
        for ext_name in &signature.name {
            if ext_name == ext {
                return !magic_number_match(&signature.magic_number, buf)
            }
        }
    }
    false
}

fn find_suspicious_files(dir: &Path, out_file_path: &Path, signatures: Vec<Signature>) -> Result<(), &'static str> {
    let mut file_paths = FileCheckResult::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.metadata().expect("Failed to get dir entry metadata").is_file() {
            match fs::File::open(entry.path()) {
                Ok(mut f) => {
                    // read up to 20 bytes
                    let mut buffer = [0; 20];
                    f.read(&mut buffer).expect("Failed to get 20 byte file buffer");
                    match entry.path().extension() {
                        Some(extension) => {
                            if is_file_mismatched(&signatures, &buffer, extension.to_str().expect("Failed to turn file extension into string")) {
                                file_paths.mismatching_extensions.push(entry.path().to_path_buf());
                            }
                        },
                        None => continue
                    }
                },
                Err(_e) => {
                    file_paths.failed_to_open.push(entry.path().to_path_buf());
                }
            }
        }
    }
    match file_paths.write_to_file(out_file_path) {
        Ok(_) => Ok(()),
        Err(e) => Err(e)
    }
}

fn main() {
    let signatures = Signature::new_from_file("extensions.txt");
    match find_suspicious_files(Path::new("./example"), Path::new("output.txt"), signatures) {
        Ok(_) => {
            println!("Program completed successfully");
        },
        Err(e) => {
            eprint!("Program failed with error: {}", e);
        }
    }
}
