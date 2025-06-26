package main

import (
	"testing"
)

func TestDecode(t *testing.T) {
	s := "$2&lt;*$I&lt;(xS2#}],[CUmC^R5HtE$UXM,UI_wd3%Y-!W$"
	out := ValueDecode(s)
	t.Logf("[%d] %s", len(out), out)
	if out != "OT93PTSQS9P6NH72" {
		t.Error()
	}
}
