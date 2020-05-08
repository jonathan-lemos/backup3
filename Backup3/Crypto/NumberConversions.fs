module Backup3.Crypto.NumberConversions

open System

let BytesToNum len func arg =
    let tmp = Seq.toArray (Seq.truncate len arg)
    if tmp.Length <> len then
        None
    else
        let tmp2 =
            match BitConverter.IsLittleEndian with
            | true -> Array.rev tmp
            | false -> tmp
        Some(func tmp2)

let BytesToU32: (seq<byte> -> uint32 option) = BytesToNum 4 (fun x ->
    uint32 (BitConverter.ToInt32(new ReadOnlySpan<byte>(x)))
)
let BytesToU16: (seq<byte> -> uint16 option) = BytesToNum 2 (fun x ->
    uint16 (BitConverter.ToInt16(new ReadOnlySpan<byte>(x)))
)

let U32ToBytes (x: uint32) =
    let res = BitConverter.GetBytes x
    match BitConverter.IsLittleEndian with
    | true -> Array.rev res
    | false -> res

let U16ToBytes (x: uint16) =
    let res = BitConverter.GetBytes x
    match BitConverter.IsLittleEndian with
    | true -> Array.rev res
    | false -> res
