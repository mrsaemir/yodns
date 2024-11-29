package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver"
	"time"
)

type reader interface {
	ReadTo(outChan chan<- resolver.Result) error
}

type writer interface {
	Wait() error
	WriteAsync(result resolver.Result) error
}

var ConvertFormat = &cobra.Command{
	Use:     "convertFormat",
	Short:   "Converts yodns output from protobuf to json and vice versa.",
	Long:    "Converts yodns output from protobuf to json and vice versa.",
	Example: "convertFormat --in 'data/scan/*.pb.zst' --out 'data/json' --size 10",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		from := Must(cmd.Flags().GetString("from"))
		out := Must(cmd.Flags().GetString("out"))
		to := Must(cmd.Flags().GetString("to"))
		size := Must(cmd.Flags().GetUint("size"))

		resultFilters := make([]FilterPredicate[resolver.Result], 0)
		if cmd.Flag("domain").Changed {
			domains := Must(cmd.Flags().GetStringSlice("domain"))
			resultFilters = append(resultFilters, DomainFilter(domains))
		}

		reader := getFilteredReaderZip(in, from, false, nil, 5*time.Minute, resultFilters...)
		writer := getWriter(out, size, to, false)

		c := make(chan resolver.Result)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(err)
			}
		}()

		for result := range c {
			if err := writer.WriteAsync(result); err != nil {
				panic(err)
			}
		}

		if err := writer.Wait(); err != nil {
			panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(ConvertFormat)

	ConvertFormat.Flags().String("in", "", "Path to the input file(s). Can be a glob pattern.")
	ConvertFormat.Flags().String("out", "", "Directory to write the output files.")
	ConvertFormat.Flags().String("from", "protobuf", "Input format. Can be 'json' or 'protobuf'. Default is 'protobuf'.")
	ConvertFormat.Flags().String("to", "json", "Output format. Can be 'json' or 'protobuf'. Default is 'json'.")
	ConvertFormat.Flags().Uint("size", 10, "Number of results that are put in each output file.")
	ConvertFormat.Flags().StringSlice("domain", []string{}, "If provided, output will only contain the resolutions for the specified domain(s).")
}
