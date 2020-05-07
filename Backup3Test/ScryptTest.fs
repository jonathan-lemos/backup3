module Backup3Test.ScryptTest

open System
open System.Text
open NUnit.Framework
open Backup3.Crypto.Scrypt
open Backup3.Crypto.Random

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
let ScryptEncryptDecrypt () =
    let par =
        { Salt = Array.zeroCreate 24
          KeyLen = uint16 32
          IvLen = uint16 16
          Log2N = uint16 14
          R = uint16 8
          P = uint16 1 }

    let pw = "abrakadabra" |> Encoding.UTF8.GetBytes
    let key, iv = Scrypt pw par

    Assert.AreEqual(par.KeyLen, key.Length)
    Assert.AreEqual(par.IvLen, iv.Length)
