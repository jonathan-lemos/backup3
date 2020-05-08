module Backup3.Enumerator

open System.Collections.Generic

let rec First<'a> (n: int) (s: IEnumerator<'a>) =
    match n with
    | x when x <= 0 -> Seq.empty<'a>
    | _ ->
        match s.MoveNext() with
        | false -> Seq.empty<'a>
        | true ->
            seq {
                yield s.Current
                yield! (First (n - 1) s)
            }

let Next<'a> (s: IEnumerator<'a>) =
    match s.MoveNext() with
    | false -> None
    | true -> Some s.Current

let rec Rest<'a> (s: IEnumerator<'a>) =
    match s.MoveNext() with
    | false -> Seq.empty<'a>
    | true ->
        seq {
            yield s.Current
            yield! (Rest s)
        }
