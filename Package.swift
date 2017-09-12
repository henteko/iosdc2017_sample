// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "iosdc2017_sample",
    dependencies: [
        .Package(url: "https://github.com/Zewo/OpenSSL.git", majorVersion: 0, minor: 14),
        ]
)
