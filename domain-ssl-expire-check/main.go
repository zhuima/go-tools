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

	cache "github.com/chenyahui/gin-cache"
	"github.com/chenyahui/gin-cache/persist"
)

type DoaminInfo struct {
	DomainName string `json:"domainName"`
}

type DomainExpireInfo struct {
	DomainName     string `json:"domain_name"`
	CreatedDate    string `json:"create_date"`
	ExpirationDate string `json:"expiration_date"`
	ExpirationDays int64  `json:"expiration_days"`
	RegistrarName  string `json:"registrar_name"`
}

type DomainSSLExpireInfo struct {
	ExpireTime     time.Time `json:"expireTime"`
	BeforeTime     time.Time `json:"beforeTime"`
	ExpirationDays int64     `json:"expiration_days"`
	DomainInfo     *DoaminInfo
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

	// 获取当前时间
	currentTime := time.Now()
	// currentTime := time.Now().Format("02/01/2006")
	// 根据过期时间求差 获取距离过期时间还剩余多少天
	difference := parse_result.Domain.ExpirationDateInTime.Sub(currentTime)

	result := &DomainExpireInfo{
		DomainName:     domainName,
		CreatedDate:    parse_result.Domain.CreatedDate,
		ExpirationDate: parse_result.Domain.ExpirationDate,
		RegistrarName:  parse_result.Registrar.Name,
		ExpirationDays: int64(difference.Hours() / 24),
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
	r := gin.New()

	r.Use(gin.Logger(), gin.Recovery())
	memoryStore := persist.NewMemoryStore(1 * time.Minute)

	r.GET("/", homePage)
	r.POST("/sslcheck", cache.CacheByRequestPath(memoryStore, 2*time.Second), sslExpireCheckEndpoint)
	r.POST("/domaincheck", cache.CacheByRequestPath(memoryStore, 2*time.Second), domainExpireCheckEndpoint)

	r.Run()
}
