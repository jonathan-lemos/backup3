module Backup3.ByteStream

open System.Collections.Generic

let rec Next (n: int) (data: IEnumerator<byte array>) (leftover: byte array) =
    match leftover.Length with
    | x when x >= n -> leftover.[..n - 1], leftover.[n..]
    | _ ->
        match data.MoveNext () with
        | false -> leftover, Array.empty<byte>
        | true ->
            match leftover.Length + data.Current.Length with
            | x when x >= n ->
                let combined = Array.concat [|leftover; data.Current|]
                combined.[..n - 1], combined.[n..]
            | _ -> 
                let combined = Array.concat [|leftover; data.Current|]
                Next n data combined
        