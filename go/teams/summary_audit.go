package teams

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

// TODO FEATUREFLAG ME?

const SummaryAuditVersion = 1

type SummaryAuditor struct {
	i int
}

type SummaryAuditStatus int

const (
	OKNoOp SummaryAuditStatus = iota
	OKRotated
	OKNotAttempted
	WillRetry
	Fatal
)

type AuditResult struct {
	Status SummaryAuditStatus
}

const SummaryAuditorTag = "SUMAUD"

func (a *SummaryAuditor) ShouldAudit(mctx libkb.MetaContext, team Team) (bool, error) {
	return team.isAdminOrOwner(mctx.CurrentUserVersion())
}

// Map of UV <-> Seqno of current PUK
type SeqnoMap = map[keybase1.UserVersion]keybase1.Seqno

func (a *SummaryAuditor) Audit(mctx libkb.MetaContext, teamID keybase1.TeamID, isPublic bool) (result AuditResult, err error) {
	mctx = mctx.WithLogTag(SummaryAuditorTag)

	team, err := Load(context.TODO(), mctx.G(), keybase1.LoadTeamArg{
		ID: teamID,
	})
	if err != nil {
		return AuditResult{}, err
	}
	if team == nil {
		return AuditResult{}, fmt.Errorf("got nil team")
	}

	shouldAudit, err := a.ShouldAudit(mctx, *team)
	if err != nil {
		return AuditResult{}, err
	}
	if !shouldAudit {
		return AuditResult{Status: OKNotAttempted}, nil
	}

	members, err := team.Members()
	if err != nil {
		return AuditResult{}, err
	}
	generationMap := make(SeqnoMap)
	for _, uv := range members.Owners {
		upak, err := loadUPAK2(context.TODO(), mctx.G(), uv.Uid, true) // TODO need force poll?
		if err != nil {
			return AuditResult{}, err
		}
		puk := upak.Current.GetLatestPerUserKey()
		if puk == nil {
			return AuditResult{}, fmt.Errorf("user has no puk")
		}
		generationMap[uv] = puk.Seqno
	}
	return AuditResult{Status: OKRotated}, nil
}
