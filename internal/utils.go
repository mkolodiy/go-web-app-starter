package internal

func PointerTo[T ~string](s T) *T {
    return &s
}