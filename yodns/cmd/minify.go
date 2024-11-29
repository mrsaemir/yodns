package cmd

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver/model"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver/serialization"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver/serialization/protobuf"
	"sync"
	"time"
)

const shortUUIDLength = 4
const longUUIDLength = 16

var Minify = &cobra.Command{
	Use:   "minify",
	Short: "Compresses yodns output by replacing UUIDs with a shorter version.",
	Long: "Compresses yodns output by replacing UUIDs with a shorter version. " +
		"This may introduce collisions of UUIDs across files and may also lead to different UUIDs for the same message in different files. " +
		"However, it significantly reduces file size while keeping the data processable. " +
		"Messages can still be uniquely identified by their metadata (i.e. a combination of question, enqueueTime, nameserverIP and node)",
	Example: "minify --in 'output_1.pb.zst' --out 'output_1_min.pb.zst'",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		outDir := Must(cmd.Flags().GetString("out"))

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, "protobuf", false, nil, 5*time.Minute)
		writer, closeFunc, err := getZipFileWriter(outDir, serialization.ZipZSTD, serialization.CompressionBest)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		// read the input file
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", in, err))
			}
		}()

		uuidIdx := newUUIDIdx(true)
		for p := range c {
			err := protobuf.SerializeResult(p, writer, func(exchange *model.MessageExchange) (*protobuf.MessageExchange, error) {
				return toMessageWithShortUUID(exchange, uuidIdx)
			})
			if err != nil {
				panic(err)
			}

		}
	},
}

// uuidIdx keeps state of UUIDs and their short form.
type uuidIdx struct {
	seenIds sync.Map
	shorts  sync.Map
	mu      sync.Mutex
	shorten bool
}

func newUUIDIdx(shorten bool) *uuidIdx {
	return &uuidIdx{
		shorten: shorten,
	}
}

// GetShortForm returns a short form of the UUID.
// If the short form collides with another UUID, the full UUID is returned.
func (idx *uuidIdx) GetShortForm(id uuid.UUID) []byte {
	if !idx.shorten {
		return id[:]
	}

	// Check
	if val, ok := idx.seenIds.Load(id); ok {
		if b, ok := val.([shortUUIDLength]byte); ok {
			return b[:]
		}
		if b, ok := val.([longUUIDLength]byte); ok {
			return b[:]
		}
	}

	// Lock
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Check
	if val, ok := idx.seenIds.Load(id); ok {
		if b, ok := val.([shortUUIDLength]byte); ok {
			return b[:]
		}
		if b, ok := val.([longUUIDLength]byte); ok {
			return b[:]
		}
	}

	// Act
	var bytes [shortUUIDLength]byte
	copy(bytes[:], id[longUUIDLength-shortUUIDLength:])

	// Short UUID has collision - store the full UUID
	if _, ok := idx.shorts.Load(bytes); ok {
		idx.seenIds.Store(id, id)
	}

	idx.seenIds.Store(id, bytes)
	idx.shorts.Store(bytes, nil)

	return bytes[:]
}

func toMessageWithShortUUID(exchange *model.MessageExchange, uuidIdx *uuidIdx) (*protobuf.MessageExchange, error) {
	result := new(protobuf.MessageExchange)
	err := result.From(exchange)

	if exchange.Metadata.ConnId != "" {
		result.Metadata.ConnId = uuidIdx.GetShortForm(uuid.MustParse(exchange.Metadata.ConnId))
	}
	result.Metadata.ParentId = uuidIdx.GetShortForm(exchange.Metadata.ParentId)
	result.Metadata.CorrelationId = uuidIdx.GetShortForm(exchange.Metadata.CorrelationId)

	return result, err
}

func init() {
	rootCmd.AddCommand(Minify)

	Minify.Flags().String("in", "", "Input file to minify.")
	Minify.MarkFlagRequired("in")

	Minify.Flags().String("out", "", "Output file.")
	Minify.MarkFlagRequired("out")
}
