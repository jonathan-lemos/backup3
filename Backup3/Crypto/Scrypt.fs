module Backup3.Crypto.Scrypt
open System
open CryptSharp.Utility
open Random
    
type ScryptParams =
    {Salt: byte[]; KeyLen: uint16; IvLen: uint16; Log2N: uint8; R: uint8; P: uint8}

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
                
    Seq.concat [|intToBytes (U16(par.KeyLen)); intToBytes (U16(par.IvLen)); intToBytes (U8(par.Log2N)); intToBytes (U8(par.R)); intToBytes (U8(par.P)); par.Salt|]

let DefaultParams () =
    {Salt=RandBytes 32; KeyLen=32; IvLen=32; Log2N=20; R=8; P=1}

let Scrypt pass par =
    let buf =
        SCrypt.ComputeDerivedKey(pass, par.Salt, (1 <<< par.KeyLen), par.R, par.P, System.Nullable(), (par.KeyLen + par.IvLen))
    buf.[0..par.KeyLen], buf.[par.IvLen..]
