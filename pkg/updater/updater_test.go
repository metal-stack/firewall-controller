package updater

import (
	"os"
	"testing"
)

func Test_copyToTempFileAndValidateChecksum(t *testing.T) {

	type args struct {
		checksum string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "cheksum match",
			args: args{
				checksum: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
			},
		},
		{
			name: "cheksum mismatch",
			args: args{
				checksum: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, _ := os.Open("./test")
			tmpFile, err := copyToTempFile(rc, "./test")
			if err != nil {
				panic(err)
			}
			defer os.Remove(tmpFile)
			err = validateChecksum(tmpFile, tt.args.checksum)

			if (err != nil) != tt.wantErr {
				t.Errorf("copyToTempFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
