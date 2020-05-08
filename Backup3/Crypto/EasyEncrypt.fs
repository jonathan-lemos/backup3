module Backup3.Crypto.EasyEncrypt

open System
open System.Collections.Generic
open System.Text
open Backup3
open Random
open Scrypt
open NumberConversions

type Password =
    | String of string
    | Bytes of byte array

let EasyEncryptParams =
    { Salt = RandBytes 32
      KeyLen = uint16 32
      Log2N = uint16 20
      R = uint16 8
      P = uint16 1 }

type EncryptResult =
    | Bytes of seq<byte array>
    | Error of string

let EasyEncrypt (password: Password) (data: seq<byte array>) =
    let pw =
        match password with
        | String s -> Encoding.UTF8.GetBytes s
        | Password.Bytes b -> b

    let par = EasyEncryptParams

    let key = Scrypt par pw
    let iv = RandBytes 16

    match Aes256Gcm.Encrypt 16 key iv data with
    | Aes256Gcm.Error e -> Error e
    | Aes256Gcm.Bytes b ->
        let x =
            fun () ->
                seq {
                    yield (SerializeParams par |> Seq.toArray)
                    yield U16ToBytes(uint16 iv.Length)
                    yield iv
                    yield! b
                }
        Bytes(x ())


let rec GetBytesRec (n: int) (data: IEnumerator<byte array>) (existing: byte array) =
    match data |> Enumerator.Next with
    | None -> existing, Array.empty<byte>
    | Some s ->
        match s.Length + existing.Length with
        | x when x >= n ->
            Array.concat
                [| existing
                   s.[..x - 1] |], s.[x..]
        | _ -> GetBytesRec n data (Array.concat [| existing; s |])

let EasyDecrypt (password: Password) (data: seq<byte array>) =
    let pw =
        match password with
        | String s -> Encoding.UTF8.GetBytes s
        | Password.Bytes b -> b

    let enum = data.GetEnumerator()

    let bytes, leftover = ByteStream.Next 4 enum Array.empty<byte>

    let len = BytesToU32 bytes
    if len.IsNone then
        Error "Byte sequence is not long enough to hold encrypted data"
    else
        let len = int len.Value

        let combined = Array.concat [| bytes; leftover |]
        let bytes, leftover = ByteStream.Next len enum combined

        let parResult = DeserializeParams bytes

        let parOption =
            match parResult with
            | Scrypt.Params b -> Some b
            | _ -> None
        if parOption.IsNone then
            Error(parResult.ToString())
        else
            let par = parOption.Value
            let key = Scrypt par pw
            let bytes, leftover = ByteStream.Next 2 enum leftover

            let ivLen = BytesToU16 bytes
            if ivLen.IsNone then
                Error "Initialization vector length not found"
            else
                let ivLen = ivLen.Value

                let bytes, leftover = ByteStream.Next (int ivLen) enum leftover
                if bytes.Length <> int ivLen then
                    Error "Reached EOF trying to read Initialization vector"
                else
                    let iv = bytes

                    match Aes256Gcm.Decrypt 16 key iv
                              (seq {
                                  yield leftover
                                  yield! Enumerator.Rest enum
                               }) with
                    | Aes256Gcm.Error e -> Error e
                    | Aes256Gcm.Bytes b -> Bytes b
