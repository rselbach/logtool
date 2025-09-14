package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    imp "logtool/internal/importer"
)

func main() {
    f, err := os.Open("./access.log")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    s := bufio.NewScanner(f)
    for i := 0; i < 10 && s.Scan(); i++ {
        line := s.Text()
        m := imp.AccessRe().FindStringSubmatch(line)
        if m == nil {
            fmt.Println("no match:", line)
        } else {
            fmt.Printf("%q %q %q %q %q %q %q %q %q %q\n", m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10])
        }
    }
}

