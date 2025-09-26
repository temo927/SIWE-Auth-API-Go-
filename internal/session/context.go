package auth

import "context"

type addrKey struct{}

func withAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, addrKey{}, addr)
}
func AddrFromCtx(ctx context.Context) string {
	v := ctx.Value(addrKey{})
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
