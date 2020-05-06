module Backup3.Enumerator

open System.Collections.Generic

let rec First<'a> (n: int) (s: IEnumerator<'a>) =
    match n with
    | 0 -> List.empty<'a>
    | _ ->
        match s.MoveNext() with
        | false -> List.empty<'a>
        | true -> s.Current :: First (n - 1) s

let Next<'a> (s: IEnumerator<'a>) =
    match s.MoveNext() with
    | false -> None
    | true -> Some s.Current

let rec Rest<'a> (s: IEnumerator<'a>) =
    match s.MoveNext() with
    | false -> List.empty<'a>
    | true -> s.Current :: Rest s
