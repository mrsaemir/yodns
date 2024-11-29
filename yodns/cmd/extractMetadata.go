package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver/serialization"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver/serialization/json"
	"os"
	"path"
	"time"
)

var ExtractMetadata = &cobra.Command{
	Use:   "extractMetadata",
	Short: "Extracts only the metadata of a given file, discarding all the actual messages.",
	Args: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		if format != "json" && format != "protobuf" {
			return fmt.Errorf("format must be either 'json' or 'protobuf'")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		format, _ := cmd.Flags().GetString("format")
		zip := Must(cmd.Flags().GetString("zip"))

		if err := os.MkdirAll(path.Dir(out), os.ModePerm); err != nil {
			panic(err)
		}

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		outWriter, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", out, err))
			}
		}()

		for p := range c {
			if err := json.SerializeResult(p, outWriter, false, false); err != nil {
				panic(fmt.Errorf("error at %v: %w", in, err))
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(ExtractMetadata)

	ExtractMetadata.Flags().String("in", "", "")
	ExtractMetadata.Flags().String("out", "messages.json", "")
	ExtractMetadata.Flags().String("format", "protobuf", "")
	ExtractMetadata.Flags().String("zip", "zstd:best", "")
}
