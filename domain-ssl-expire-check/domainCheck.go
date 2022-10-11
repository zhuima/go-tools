package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	// whois "github.com/undiabler/golang-whois"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

var (
	DomainName string
	logLevel   string
)

type DomainInfo struct {
	DomainName     string `json:"domain_name"`
	CreatedDate    string `json:"create_date"`
	ExpirationDate string `json:"expiration_date"`
	RegistrarName  string `json:"registrar_name"`
}

func init() {
	flag.StringVar(&logLevel, "loglevel", "DEBUG", "set log level value")
	flag.StringVar(&logLevel, "l", "DEBUG", "set log level value (shorthand)")
	flag.StringVar(&DomainName, "name", "", "Enter a Domain Name: [baidu.com]")
	flag.StringVar(&DomainName, "n", "", "Enter a Domain Name: [baidu.com]")
	flag.Usage = usage
	flag.Parse()
}

func usage() {
	fmt.Print("whois check v1.0\n")
	flag.PrintDefaults()
}

func main() {

	if len(DomainName) == 0 {
		fmt.Println("Usage: domainCheck.go -n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 大小写转换，避免用户误输入
	// 判断用户是否是输入的顶级域名，如果不是则需要处理下,这里使用副本的形式进行截取，避免内存不回收现象
	realname := make([]string, 2)
	splitDomainName := strings.Split(strings.ToLower(DomainName), ".")
	copy(realname, splitDomainName[(len(splitDomainName)-2):])
	fmt.Println("realname", strings.Join(realname, "."))
	whois_result, err := whois.Whois(strings.Join(realname, "."))
	if err != nil {
		fmt.Println("Error in whois lookup : %v ", err)
		os.Exit(1)
	}

	// fmt.Println(result)

	result, err := whoisparser.Parse(whois_result)
	if err != nil {
		fmt.Println("Error in whois Parse : %v ", err)
		os.Exit(1)
	}

	domaininfo := &DomainInfo{
		DomainName:     DomainName,
		CreatedDate:    result.Domain.CreatedDate,
		ExpirationDate: result.Domain.ExpirationDate,
		RegistrarName:  result.Registrar.Name,
	}

	if logLevel == "INFO" {
		fmt.Println("just only test")
	}
	// fmt.Println(domaininfo)
	// fmt.Println(json.Marshal(domaininfo))
	b, err := json.MarshalIndent(domaininfo, "", "   ")
	if err != nil {
		fmt.Println("json err:", err)
	}
	fmt.Println(string(b))

}
