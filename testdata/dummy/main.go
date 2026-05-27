package main

import (
	"fmt"
	"github.com/go-resty/resty"
)

func main() {
	client := resty.New()
	fmt.Println(client)
}
