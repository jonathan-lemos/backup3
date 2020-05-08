module Backup3.Crypto.Aes256Gcm

open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Modes
open Org.BouncyCastle.Crypto.Parameters


type Result =
    | Bytes of seq<byte array>
    | Error of string

let Process (encrypt: bool) (macLen: int) (key: byte array) (iv: byte array) (data: seq<byte array>) =
    let macLen = macLen * 8
    
    if key.Length <> 32 then
        Error "Key length must be 32"
    else
        let x =
            fun () ->
                seq {
                    let cipher = GcmBlockCipher(AesEngine())
                    let par = AeadParameters((KeyParameter(key)), macLen, iv, Array.empty<byte>)

                    cipher.Init(encrypt, par)

                    for block in data do
                        let buf = Array.zeroCreate<byte> (cipher.GetUpdateOutputSize(block.Length))
                        let len = cipher.ProcessBytes(block, 0, block.Length, buf, 0)
                        assert (len = buf.Length)
                        yield buf

                    let tag = Array.zeroCreate<byte> (cipher.GetOutputSize 0)
                    let len = cipher.DoFinal(tag, 0)
                    assert (len = tag.Length)

                    yield tag
                }
        Bytes(x ())

let Encrypt: int -> byte array -> byte array -> seq<byte array> -> Result = Process true
let Decrypt: int -> byte array -> byte array -> seq<byte array> -> Result = Process false
