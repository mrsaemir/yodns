package protobuf

import (
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"testing"
)

func TestReader_ReadTo(t *testing.T) {
	zip := serialization.ZipZSTD
	r, _ := NewFileReader("C:\\Users\\fsteurer.LAP-21-0158\\Documents\\dnsmonitor\\experiments\\data\\scan\\2023-11-20-14-02_57570d8\\scan\\output_0_b348476b.pb.zst")
	r.Zip = &zip

	fmt.Sprintf("ttttt")
	out := make(chan resolver.Result)
	go func() {
		if err := r.ReadTo(out); err != nil {
			panic(err)
		}
	}()

	for result := range out {
		fmt.Println(result.Domains)
	}
}
