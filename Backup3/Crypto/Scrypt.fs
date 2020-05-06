module Backup3.Crypto.Scrypt
open System
open System.Linq
open Backup3
open CryptSharp.Utility
open Random
    
type ScryptParams =
    {Salt: byte[]; KeyLen: uint16; IvLen: uint16; Log2N: uint8; R: uint8; P: uint8}

let ScryptMagicHeader = [|byte 0xB3; byte 'P'; byte 'W'; byte 'S'|]
let ScryptBaseLength = 4 + ScryptMagicHeader.Length + 2 + 2 + 1 + 1 + 1

type UInt =
    | U32 of uint32
    | U16 of uint16
    | U8 of uint8

let SerializeParams par =
    let intToBytes (i: UInt) =
        let bytes =
            match i with
            | U8 u -> [|u|]
            | U16 u -> BitConverter.GetBytes(u)
            | U32 u -> BitConverter.GetBytes(u)
                 
        match BitConverter.IsLittleEndian with
            | true -> bytes |> Array.rev
            | false -> bytes
    
    let len = U32 (uint32 (ScryptBaseLength + par.Salt.Length))
                
    Seq.concat [|intToBytes len; ScryptMagicHeader; intToBytes (U16 par.KeyLen); intToBytes (U16 par.IvLen); intToBytes (U8 par.Log2N); intToBytes (U8 par.R); intToBytes (U8 par.P); par.Salt|]

type ParamResult =
    | Params of ScryptParams
    | RequiredLength of int
    | Invalid

let DeserializeParams (bytes: seq<byte>) =
    let bytesToNum len func arg =
        let tmp = Seq.toArray (Seq.truncate len arg)
        if tmp.Length <> len then None else
        let tmp2 =
            match BitConverter.IsLittleEndian with
            | true -> Array.rev tmp
            | false -> tmp
        Some (func(new ReadOnlySpan<byte> (tmp2)))
    
    let bytesToU32 = bytesToNum 4 BitConverter.ToInt32
    let bytesToU16 = bytesToNum 2 BitConverter.ToInt16
    
    let enum = bytes.GetEnumerator()
    
    let len = bytesToU32 (enum |> Enumerator.First 4)
    let header = enum |> Enumerator.First 4
    let keyLen = bytesToU16 (enum |> Enumerator.First 2)
    let ivLen = bytesToU16 (enum |> Enumerator.First 2)
    let log2N = enum |> Enumerator.Next
    let r = enum |> Enumerator.Next
    let p = enum |> Enumerator.Next
    let salt = enum |> Enumerator.Rest
    
    if len = None then
        RequiredLength 4
    else
    
    if header.Length <> 4 ||
       keyLen = None ||
       ivLen = None ||
       log2N = None ||
       r = None then
       RequiredLength ScryptBaseLength
    else
    
    if salt.Length < len.Value - ScryptBaseLength then
        RequiredLength len.Value
    else
    
    if header <> List.ofArray ScryptMagicHeader then
        Invalid
    else
        Params {Salt=List.toArray salt; KeyLen=uint16 keyLen.Value; IvLen=uint16 ivLen.Value; Log2N=uint8 log2N.Value; R=uint8 r.Value; P=uint8 p.Value}

let DefaultParams () =
    {Salt=RandBytes 32; KeyLen=uint16 32; IvLen=uint16 32; Log2N=uint8 20; R=uint8 8; P=uint8 1}

let Scrypt pass par =
    let buf =
        SCrypt.ComputeDerivedKey(pass, par.Salt, (1 <<< int32 par.KeyLen), int32 par.R, int32 par.P, System.Nullable (), int32 par.KeyLen + par.IvLen)
    buf.[0..int(par.KeyLen)], buf.[int(par.IvLen)..]
