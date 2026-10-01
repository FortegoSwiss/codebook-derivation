package recoverycode

import "testing"

func FuzzParse(f *testing.F) {
	f.Add("01RF7J344K47T5S6YZEANNWHZ9YMKV")
	f.Add("01RF7-J344K-47T5S-6YZEA-NNWHZ-9YMKV")
	f.Add("01rf7j344k47t5s6yzeannwhz9ymkv")
	f.Add("")
	f.Add("not-a-recovery-code")

	f.Fuzz(func(t *testing.T, input string) {
		code, err := Parse(input)
		if err != nil {
			return
		}

		canonical := code.WireString()
		roundTrip, err := Parse(canonical)
		if err != nil {
			t.Fatalf("canonical output cannot be parsed: %v", err)
		}
		if roundTrip.BatchNumber() != code.BatchNumber() || roundTrip.Data() != code.Data() {
			t.Fatal("canonical round trip changed Recovery Code fields")
		}
	})
}
