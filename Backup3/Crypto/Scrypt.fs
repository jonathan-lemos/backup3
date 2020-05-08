module Backup3.Crypto.Scrypt

open System
open Backup3
open Norgerman.Cryptography.Scrypt
open Random
open NumberConversions

type ScryptParams =
    { Salt: byte []
      KeyLen: uint16
      Log2N: uint16
      R: uint16
      P: uint16 }

let ScryptMagicHeader =
    [| byte 0xB3
       byte 'P'
       byte 'W'
       byte 'S' |]

let ScryptBaseLength = 4 + ScryptMagicHeader.Length + 2 + 2 + 2 + 2

let SerializeParams par =
    let len = uint32 (ScryptBaseLength + par.Salt.Length)

    Seq.concat
        [| U32ToBytes len
           ScryptMagicHeader
           U16ToBytes par.KeyLen
           U16ToBytes par.Log2N
           U16ToBytes par.R
           U16ToBytes par.P
           par.Salt |]

type ParamResult =
    | Params of ScryptParams
    | RequiredLength of int
    | Invalid

let DeserializeParams (bytes: seq<byte>) =
    let enum = bytes.GetEnumerator()

    let len = BytesToU32(enum |> Enumerator.First 4)

    if len = None then
        RequiredLength 4
    else

        let header = enum |> Enumerator.First 4 |> Seq.toList
        let keyLen = BytesToU16(enum |> Enumerator.First 2)
        let log2N = BytesToU16(enum |> Enumerator.First 2)
        let r = BytesToU16(enum |> Enumerator.First 2)
        let p = BytesToU16(enum |> Enumerator.First 2)
        let salt = enum |> Enumerator.First(int (len.Value - uint32 ScryptBaseLength)) |> Seq.toList

        if header.Length <> 4 || keyLen = None || log2N = None || r = None then
            RequiredLength (int len.Value)
        else

        if salt.Length < int (len.Value - uint32 ScryptBaseLength) then
            RequiredLength (int len.Value)
        else

        if header <> List.ofArray ScryptMagicHeader then
            Invalid
        else
            Params
                { Salt = List.toArray salt
                  KeyLen = uint16 keyLen.Value
                  Log2N = uint16 log2N.Value
                  R = uint16 r.Value
                  P = uint16 p.Value }

let DefaultParams () =
    { Salt = RandBytes 32
      KeyLen = uint16 32
      Log2N = uint16 20
      R = uint16 8
      P = uint16 1 }

let Scrypt (par: ScryptParams) (pass: byte array) =
    let buf =
        ScryptUtil.Scrypt
            (pass, par.Salt, (1 <<< int32 par.Log2N), int32 par.R, int32 par.P, int32 par.KeyLen)
    buf
    // SCrypt.ComputeDerivedKey(pass, par.Salt, (1 <<< int32 par.Log2N), int32 par.R, int32 par.P, System.Nullable (), int32 (par.KeyLen + par.IvLen))
