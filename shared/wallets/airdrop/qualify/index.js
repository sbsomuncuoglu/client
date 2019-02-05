// @flow
import * as React from 'react'
import * as Kb from '../../../common-adapters'
import * as Types from '../../../constants/types/wallets'
import * as Constants from '../../../constants/wallets'
import * as Styles from '../../../styles'
import openURL from '../../../util/open-url'
import shallowEqual from 'shallowequal'

type Props = {|
  state: Types.AirdropState,
  onCancel: () => void,
  onLoad: () => void,
  onSubmit: () => void,
  rows: $ReadOnlyArray<{|
    title: string,
    subTitle: string,
    valid: boolean,
  |}>,
|}

const Accepted = p =>
  Styles.isMobile && p.state !== 'accepted' ? null : (
    <Kb.ScrollView
      style={styles.scrollView}
      className={Styles.classNames({
        'fade-anim-enter': true,
        'fade-anim-enter-active': p.state === 'accepted',
      })}
    >
      <Kb.Box2 noShrink={true} fullWidth={true} direction="vertical" style={styles.content} gap="medium">
        <Kb.Box2 direction="vertical" style={styles.grow} />
        <Kb.Icon type="icon-fancy-airdrop-star-shining-happy-120" style={styles.star} />
        <Kb.Box2 direction="vertical" gap="xtiny" fullWidth={true} alignItems="center">
          <Kb.Text backgroundMode="Terminal" center={true} type="Header">
            You're in!
          </Kb.Text>
          <Kb.Text backgroundMode="Terminal" center={true} type="Body">
            Your Lumens will show up in your default wallet account.
          </Kb.Text>
        </Kb.Box2>
        <Kb.Box2 direction="vertical" style={styles.grow} />
        <Kb.Divider />
        <Kb.Box2 direction="vertical" style={styles.grow} />
        <Kb.Box2 direction="vertical" gap="xtiny" fullWidth={true} alignItems="center">
          <Kb.Text backgroundMode="Terminal" center={true} type="BodySemibold">
            Now bring your friends!
          </Kb.Text>
          <Kb.Box2 direction={Styles.isMobile ? 'vertical' : 'horizontal'}>
            <Kb.Text backgroundMode="Terminal" center={true} type="Body" style={styles.friendText}>
              Share this link:{' '}
            </Kb.Text>
            <Kb.Text
              backgroundMode="Terminal"
              center={true}
              type="BodyPrimaryLink"
              onClick={() => openURL('https://keybase.io/airdrop')}
              selectable={true}
            >
              https://keybase.io/airdrop
            </Kb.Text>
          </Kb.Box2>
        </Kb.Box2>
        <Kb.Box2 direction="vertical" style={styles.grow} />
        <Kb.Button
          onClick={p.onCancel}
          fullWidth={true}
          type="Wallet"
          label="Close"
          style={styles.buttonClose}
        />
      </Kb.Box2>
    </Kb.ScrollView>
  )

const Row = p => (
  <Kb.Box2
    noShrink={true}
    direction="vertical"
    fullWidth={true}
    style={Styles.collapseStyles([styles.row, !p.first && styles.rowBorder])}
  >
    <Kb.Box2 noShrink={true} direction="horizontal" fullWidth={true}>
      <Kb.Text type="BodySemibold" style={styles.rowText}>
        {p.title}
      </Kb.Text>
      {p.loading && <Kb.ProgressIndicator style={styles.progress} white={true} />}
      {!p.loading && (
        <Kb.Icon
          type={p.valid ? 'iconfont-check' : 'iconfont-close'}
          color={p.valid ? Styles.globalColors.green : Styles.globalColors.red}
          sizeType={'Default'}
        />
      )}
    </Kb.Box2>
    {!p.loading && !!p.subTitle && (
      <Kb.Text type="Body" style={styles.rowText}>
        {p.subTitle}
      </Kb.Text>
    )}
  </Kb.Box2>
)

type State = {|
  rowIdxLoaded: number,
|}
class Qualified extends React.PureComponent<Props, State> {
  state = {
    rowIdxLoaded: -1,
  }
  _loadingTimerID: ?TimeoutID

  _kickNextLoad = () => {
    if (__STORYSHOT__) {
      return
    }
    this._loadingTimerID && clearTimeout(this._loadingTimerID)
    this._loadingTimerID = undefined
    if (this.state.rowIdxLoaded >= this.props.rows.length - 1) {
      return
    }

    // wait extra long on last row
    if (this.state.rowIdxLoaded === this.props.rows.length - 2) {
      this._loadingTimerID = setTimeout(() => this.setState(p => ({rowIdxLoaded: p.rowIdxLoaded + 1})), 2500)
    } else {
      this._loadingTimerID = setTimeout(() => this.setState(p => ({rowIdxLoaded: p.rowIdxLoaded + 1})), 1000)
    }
  }

  componentWillUnmount() {
    this._loadingTimerID && clearTimeout(this._loadingTimerID)
    this._loadingTimerID = undefined
  }

  componentDidMount() {
    this._kickNextLoad()
  }

  componentDidUpdate(prevProps, prevState) {
    // got new rows or more to load
    if (!shallowEqual(this.props.rows, prevProps.rows)) {
      this.setState({rowIdxLoaded: -1})
      this._kickNextLoad()
    } else if (this.state.rowIdxLoaded < this.props.rows.length) {
      this._kickNextLoad()
    }
  }

  render() {
    const p = this.props
    const rows = this.props.rows
    const loadingRows = !!rows.length && this.state.rowIdxLoaded < rows.length - 1
    const loading = p.state === 'loading' || !!loadingRows

    if (Styles.isMobile && p.state === 'accepted') {
      return null
    }

    return (
      <Kb.ScrollView
        style={styles.scrollView}
        className={Styles.classNames({
          'fade-anim-enter': true,
          'fade-anim-enter-active': p.state !== 'accepted',
        })}
      >
        <Kb.Box2 noShrink={true} direction="vertical" fullWidth={true} gap="tiny" style={styles.content}>
          <>
            <Kb.Box2 direction="vertical" style={styles.grow} />
            <Kb.Icon
              type={
                loading
                  ? 'icon-fancy-airdrop-star-faded-loading-120'
                  : p.state === 'qualified'
                  ? 'icon-fancy-airdrop-star-shining-happy-120'
                  : 'icon-fancy-airdrop-star-faded-sad-120'
              }
              style={styles.star}
            />
          </>
          <Kb.Text
            center={true}
            type={loading ? 'BodySmallSemibold' : 'Header'}
            style={loading ? styles.loadingText : styles.headerText}
          >
            {loading
              ? 'Analyzing your account...'
              : p.state === 'qualified'
              ? 'You are qualified to join!'
              : 'Sorry, you are not qualified to join.'}
          </Kb.Text>
          <>
            <Kb.Box2 direction="vertical" style={styles.grow} />
            <Kb.Box2
              direction="vertical"
              className={Styles.classNames({
                growFadeInBig: rows.length,
                growFadeInSmall: true,
              })}
            >
              {rows.map((r, idx) => (
                <Row key={r.title} {...r} first={idx === 0} loading={idx > this.state.rowIdxLoaded} />
              ))}
            </Kb.Box2>
            <Kb.Box2 direction="vertical" style={styles.grow} />
          </>
          {p.state === 'qualified' && !loading && (
            <Kb.WaitingButton
              onClick={p.onSubmit}
              fullWidth={true}
              type="PrimaryGreen"
              label="Become a lucky airdropee"
              disabled={loadingRows}
              waitingKey={Constants.airdropWaitingKey}
              style={styles.buttonAccept}
            />
          )}
          <Kb.Button
            onClick={p.onCancel}
            fullWidth={true}
            type="Wallet"
            label="Close"
            style={styles.buttonClose}
          />
        </Kb.Box2>
      </Kb.ScrollView>
    )
  }
}

class Qualify extends React.PureComponent<Props> {
  componentDidMount() {
    this.props.onLoad()
  }
  render() {
    return (
      <Kb.MaybePopup onClose={this.props.onCancel}>
        <Kb.Box2 direction="vertical" fullWidth={true} fullHeight={true} style={styles.container}>
          <Accepted {...this.props} />
          <Qualified {...this.props} />
        </Kb.Box2>
      </Kb.MaybePopup>
    )
  }
}

const styles = Styles.styleSheetCreate({
  buttonAccept: {flexGrow: 0},
  buttonClose: {
    backgroundColor: Styles.globalColors.black_20,
    flexGrow: 0,
  },
  container: Styles.platformStyles({
    common: {backgroundColor: Styles.globalColors.purple2},
    isElectron: {
      height: 550,
      width: 400,
    },
    isMobile: {
      height: '100%',
      width: '100%',
    },
  }),
  content: Styles.platformStyles({
    isElectron: {
      minHeight: 550,
      padding: Styles.globalMargins.medium,
    },
    isMobile: {
      minHeight: '100%',
      padding: Styles.globalMargins.small,
    },
  }),
  friendText: Styles.platformStyles({
    isElectron: {whiteSpace: 'pre'},
  }),
  grow: {
    flexGrow: 1,
    flexShrink: 1,
    width: 100,
  },
  headerText: {color: Styles.globalColors.white},
  loadingText: {color: Styles.globalColors.white_40},
  progress: {
    color: Styles.globalColors.white,
    height: 20,
    width: 20,
  },
  row: Styles.platformStyles({
    isElectron: {
      minHeight: Styles.globalMargins.large,
      paddingBottom: Styles.globalMargins.xsmall,
      paddingTop: Styles.globalMargins.xsmall,
    },
    isMobile: {
      paddingBottom: Styles.globalMargins.xsmall,
      paddingLeft: Styles.globalMargins.tiny,
      paddingRight: Styles.globalMargins.tiny,
      paddingTop: Styles.globalMargins.xsmall,
    },
  }),
  rowBorder: {
    borderStyle: 'solid',
    borderTopColor: Styles.globalColors.black_10,
    borderTopWidth: 1,
  },
  rowText: {
    color: Styles.globalColors.white,
    flexGrow: 1,
    flexShrink: 1,
    marginRight: Styles.globalMargins.medium,
  },
  scrollView: {...Styles.globalStyles.fillAbsolute},
  star: {
    alignSelf: 'center',
    height: 120,
    width: 120,
  },
})

export default Qualify
