fn main() {
    let current_dir = std::env::current_dir().unwrap();
    let protoc_path = current_dir.join("protoc/bin/protoc.exe");
    if protoc_path.exists() {
        std::env::set_var("PROTOC", protoc_path);
    }

    prost_build::compile_protos(&["proto/handshake.proto"], &["proto/"]).unwrap();
}
