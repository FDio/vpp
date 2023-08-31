package main

import (
	"io"
	"os"
	"strings"
)

const networkTopologyDir string = "topo-network/"
const containerTopologyDir string = "topo-containers/"

type Stanza struct {
	content string
	pad     int
}

type ActionResult struct {
	Err       error
	Desc      string
	ErrOutput string
	StdOutput string
}

type JsonResult struct {
	Code      int
	Desc      string
	ErrOutput string
	StdOutput string
}

func (c *Stanza) NewStanza(name string) *Stanza {
	c.Append("\n" + name + " {")
	c.pad += 2
	return c
}

func (c *Stanza) Append(name string) *Stanza {
	c.content += strings.Repeat(" ", c.pad)
	c.content += name + "\n"
	return c
}

func (c *Stanza) Close() *Stanza {
	c.content += "}\n"
	c.pad -= 2
	return c
}

func (s *Stanza) ToString() string {
	return s.content
}

func (s *Stanza) SaveToFile(fileName string) error {
	fo, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer fo.Close()

	_, err = io.Copy(fo, strings.NewReader(s.content))
	return err
}
