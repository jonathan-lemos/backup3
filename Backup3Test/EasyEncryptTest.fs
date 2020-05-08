module Backup3Test.EasyEncryptTest

open Backup3.Crypto
open NUnit.Framework
open Backup3.Crypto.EasyEncrypt


[<SetUp>]
let Setup () =
    ()

[<Test>]
let EasyEncryptDecryptTest () =
    let bigData =
        (seq { 1 .. 3 }
         |> Seq.map (fun i ->
             seq { i .. 65535 + i }
             |> Seq.map (fun j -> byte j)
             |> Seq.toArray))
        |> Seq.toArray

    let is = bigData |> Array.concat

    let password = "abcakadabra"

    let enc = EasyEncrypt (String password) bigData

    let encRes =
        match enc with
        | Bytes b -> b
        | Error e ->
            Assert.Fail e
            Seq.empty<byte array>
        |> Seq.toArray

    let dec = EasyDecrypt (String password) encRes

    let decRes =
        match dec with
        | Bytes b -> b
        | Error e ->
            Assert.Fail e
            Seq.empty<byte array>
        |> Seq.toArray

    let ds = decRes |> Array.concat

    Assert.AreEqual(is, ds)
    ()
