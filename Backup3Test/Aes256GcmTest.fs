module Backup3Test.Aes256GcmTest

open NUnit.Framework
open Backup3.Crypto.Aes256Gcm


[<SetUp>]
let Setup () =
    ()

[<Test>]
let Aes256GcmEncryptDecrypt () =
    let bigData =
        (seq { 1 .. 3 }
        |> Seq.map (fun i ->
            seq { i .. 65535 + i }
            |> Seq.map (fun j -> byte j)
            |> Seq.toArray))
        |> Seq.toArray
        
    let is = bigData |> Array.concat

    let key =
        seq { 0 .. 31 }
        |> Seq.map (fun j -> byte j)
        |> Seq.toArray

    let iv =
        seq { 0 .. 10 .. 150 }
        |> Seq.map (fun j -> byte j)
        |> Seq.toArray

    let enc =
        (match Encrypt 128 key iv bigData with
        | Bytes b -> b
        | Error s ->
            Assert.Fail(s)
            Array.empty<byte array> |> Array.toSeq)
        |> Seq.toArray

    let dec =
        (match Decrypt 128 key iv enc with
         | Bytes b -> b
         | Error s ->
             Assert.Fail(s)
             Array.empty<byte array> |> Array.toSeq)
        |> Array.concat
    
    Assert.AreEqual(is, dec)
