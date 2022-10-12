package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

var (
	DomainName string
)

type DoaminInfo struct {
	DomainName string `json:"domainName"`
}

type DomainSSLExpireInfo struct {
	ExpireTime     time.Time `json:"expireTime"`
	BeforeTime     time.Time `json:"beforeTime"`
	ExpirationDays int64     `json:"expiration_days"`
	DomainInfo     *DoaminInfo
}

func init() {
	flag.StringVar(&DomainName, "name", "", "Enter a Domain Name: [baidu.com]")
	flag.StringVar(&DomainName, "n", "", "Enter a Domain Name: [baidu.com]")
	flag.Usage = usage
	flag.Parse()
}

func usage() {
	fmt.Print("ssl check v1.0\n")
	flag.PrintDefaults()
}

func main() {

	if len(DomainName) == 0 {
		fmt.Println("Usage: sslCheck.go -n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	domaininfo, err := sslCheck(DomainName)
	if err != nil {
		fmt.Printf("%s check failed, the reason is: %s\n", DomainName, err.Error())
		os.Exit(10)
	}

	b, err := json.MarshalIndent(domaininfo, "", "   ")
	if err != nil {
		fmt.Println("JSON Marshal err:", err)
		os.Exit(20)
	}
	fmt.Println(string(b))

}

func sslCheck(domainName string) (DomainSSLExpireInfo, error) {
	var domainsslexpireinfo DomainSSLExpireInfo

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domainName), nil)
	if err != nil {
		return domainsslexpireinfo, err
	}

	expireTime := conn.ConnectionState().PeerCertificates[0].NotAfter
	beforeTime := conn.ConnectionState().PeerCertificates[0].NotBefore

	// 获取当前时间
	currentTime := time.Now()
	// currentTime := time.Now().Format("02/01/2006")
	// 根据过期时间求差 获取距离过期时间还剩余多少天
	difference := conn.ConnectionState().PeerCertificates[0].NotAfter.Sub(currentTime)

	result := &DomainSSLExpireInfo{
		ExpireTime: expireTime,
		BeforeTime: beforeTime,
		DomainInfo: &DoaminInfo{
			DomainName: domainName,
		},
		ExpirationDays: int64(difference.Hours() / 24),
	}
	return *result, nil
}
