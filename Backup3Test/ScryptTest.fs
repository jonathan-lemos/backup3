module Backup3Test.ScryptTest

open System.Text
open NUnit.Framework
open Backup3.Crypto.Scrypt

[<SetUp>]
let Setup () =
    ()

[<Test>]
let ScryptSerializeDeserialize () =
    let par = DefaultParams()
    let x = SerializeParams par |> Seq.toList
    let y = DeserializeParams x

    let z =
        match y with
        | Params p -> p
        | _ ->
            Assert.Fail()
            DefaultParams()

    Assert.AreEqual(par, z)
    Assert.Pass()
    ()

[<Test>]
let ScryptSerializeDeserializeExtra () =
    let par = DefaultParams()
    let x = (SerializeParams par |> Seq.toList) @ (Array.zeroCreate<byte> 4 |> Array.toList)
    let y = DeserializeParams x

    let z =
        match y with
        | Params p -> p
        | _ ->
            Assert.Fail()
            DefaultParams()

    Assert.AreEqual(par, z)
    Assert.Pass()
    ()

[<Test>]
let ScryptSerializeDeserializeLen () =
    let par = DefaultParams()
    let x = (SerializeParams par |> Seq.toList) @ (Array.zeroCreate<byte> 4 |> Array.toList)
    let y = DeserializeParams (List.truncate 4 x)

    let z =
        match y with
        | RequiredLength r -> r
        | _ ->
            Assert.Fail()
            0

    Assert.AreEqual(ScryptBaseLength + par.Salt.Length, z)
    Assert.Pass()
    ()

[<Test>]
let ScryptEncryptDecrypt () =
    let par =
        { Salt = Array.zeroCreate 24
          KeyLen = uint16 32
          Log2N = uint16 14
          R = uint16 8
          P = uint16 1 }

    let pw = "abrakadabra" |> Encoding.UTF8.GetBytes
    let key = Scrypt par pw

    Assert.AreEqual(par.KeyLen, key.Length)
    ()
