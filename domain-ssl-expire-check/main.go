package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type DoaminInfo struct {
	DomainName string `json:"domainName"`
}

type DomainExpireInfo struct {
	DomainName     string `json:"domain_name"`
	CreatedDate    string `json:"create_date"`
	ExpirationDate string `json:"expiration_date"`
	RegistrarName  string `json:"registrar_name"`
}

type DomainSSLExpireInfo struct {
	ExpireTime time.Time `json:"expireTime"`
	BeforeTime time.Time `json:"beforeTime"`
	DomainInfo *DoaminInfo
}

func domainCheck(domainName string) (DomainExpireInfo, error) {
	var domainexpireinfo DomainExpireInfo

	// 大小写转换，避免用户误输入
	// 判断用户是否是输入的顶级域名，如果不是则需要处理下,这里使用副本的形式进行截取，避免内存不回收现象
	realname := make([]string, 2)
	splitDomainName := strings.Split(strings.ToLower(domainName), ".")
	copy(realname, splitDomainName[(len(splitDomainName)-2):])
	whois_result, err := whois.Whois(strings.Join(realname, "."))
	if err != nil {

		return domainexpireinfo, errors.New(fmt.Sprintf("Error in whois lookup : %v ", err))
	}

	// fmt.Println(result)

	parse_result, err := whoisparser.Parse(whois_result)
	if err != nil {
		return domainexpireinfo, errors.New(fmt.Sprintf("Error in whois Parse : %v ", err))
	}

	result := &DomainExpireInfo{
		DomainName:     domainName,
		CreatedDate:    parse_result.Domain.CreatedDate,
		ExpirationDate: parse_result.Domain.ExpirationDate,
		RegistrarName:  parse_result.Registrar.Name,
	}

	return *result, nil
}

func sslCheck(domainName string) (DomainSSLExpireInfo, error) {
	var domainsslexpireinfo DomainSSLExpireInfo

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domainName), nil)
	if err != nil {
		return domainsslexpireinfo, err
	}

	// fmt.Println("info", conn.ConnectionState().PeerCertificates[0])
	expireTime := conn.ConnectionState().PeerCertificates[0].NotAfter
	beforeTime := conn.ConnectionState().PeerCertificates[0].NotBefore
	// domainexpireinfo.ExpireTime = expireTime
	// domainexpireinfo.BeforeTime = beforeTime
	// domainexpireinfo.DomainInfo.DomainName = domainName

	result := &DomainSSLExpireInfo{
		ExpireTime: expireTime,
		BeforeTime: beforeTime,
		DomainInfo: &DoaminInfo{
			DomainName: domainName,
		},
	}
	return *result, nil
}

func homePage(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "home page",
		"status":  "success",
	})
}

func sslExpireCheckEndpoint(c *gin.Context) {
	var domainInfo DoaminInfo
	if err := c.ShouldBindJSON(&domainInfo); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"status":  "failed",
			"data":    make([]interface{}, 0),
		})
	}
	resp, err := sslCheck(domainInfo.DomainName)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"status":  "failed",
			"data":    make([]interface{}, 0),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("check %s", domainInfo.DomainName),
		"status":  "success",
		"data":    resp,
	})
}

func domainExpireCheckEndpoint(c *gin.Context) {
	var domainInfo DoaminInfo
	if err := c.ShouldBindJSON(&domainInfo); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"status":  "failed",
			"data":    make([]interface{}, 0),
		})
	}
	resp, err := domainCheck(domainInfo.DomainName)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"status":  "failed",
			"data":    make([]interface{}, 0),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("check %s", domainInfo.DomainName),
		"status":  "success",
		"data":    resp,
	})
}

func main() {
	r := gin.Default()
	r.GET("/", homePage)
	r.POST("/sslcheck", sslExpireCheckEndpoint)
	r.POST("/domaincheck", domainExpireCheckEndpoint)

	r.Run()
}
