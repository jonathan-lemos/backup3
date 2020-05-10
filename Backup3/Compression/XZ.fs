module Backup3.Compression.XZ

open System
open System.IO
open XZ.NET


let Compress (level: int) (extreme: bool) (data: seq<byte array>) =
    let ms = new MemoryStream ()
    let xs = new XZOutputStream (ms)
    seq {
        for block in data do
            let buf = Array.zeroCreate<byte> (block.Length * 2 + 64)
            let len = xs.Write (new ReadOnlySpan<byte> (block))
            yield buf.[..len - 1]
    }

