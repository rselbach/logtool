package main

import (
    "bufio"
    "flag"
    "fmt"
    "log"
    "os"
    "strings"

    "golang.org/x/crypto/bcrypt"
)

func main() {
    var (
        password = flag.String("password", "", "Password to hash (omit to read from stdin)")
        cost     = flag.Int("cost", 12, "bcrypt cost (10-16 typical)")
    )
    flag.Parse()

    pass := *password
    if pass == "" {
        // Read from stdin (first line, no newline)
        info, _ := os.Stdin.Stat()
        if (info.Mode() & os.ModeCharDevice) != 0 {
            log.Fatalf("no -password provided and stdin is a TTY; pass via -password or pipe via stdin")
        }
        rd := bufio.NewReader(os.Stdin)
        s, err := rd.ReadString('\n')
        if err != nil && err.Error() != "EOF" { log.Fatal(err) }
        pass = strings.TrimRight(s, "\r\n")
    }
    if pass == "" { log.Fatalf("empty password") }
    if *cost < bcrypt.MinCost { *cost = bcrypt.MinCost }
    if *cost > 16 { *cost = 16 }
    out, err := bcrypt.GenerateFromPassword([]byte(pass), *cost)
    if err != nil { log.Fatal(err) }
    fmt.Println(string(out))
}

