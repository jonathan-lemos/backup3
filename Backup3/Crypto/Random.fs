module Backup3.Crypto.Random

open System.Security.Cryptography

let RandBytes len =
    let ret : byte array = Array.zeroCreate len
    let rng = new RNGCryptoServiceProvider()
    rng.GetBytes ret
    ret
    