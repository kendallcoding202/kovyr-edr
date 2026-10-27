package sample

import "github.com/kendallcoding202/kovyr-edr/proof/note"

func noteSigLines(signed string) ([]note.SigLine, error) {
	n, err := note.Parse(signed)
	if err != nil {
		return nil, err
	}
	return n.Sigs, nil
}
