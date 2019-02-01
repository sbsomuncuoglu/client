// @flow
import * as React from 'react'
import * as Kb from '../../common-adapters'
import * as Constants from '../../constants/wallets'
import * as Styles from '../../styles'
import {iconMeta} from '../../common-adapters/icon.constants'
import openURL from '../../util/open-url'

type Props = {|
  loading: boolean,
  onBack: () => void,
  onLoad: () => void,
  onCheckQualify: () => void,
  onReject: () => void,
  signedUp: boolean,
  headerBody: string,
  headerTitle: string,
  sections: $ReadOnlyArray<{|
    lines: $ReadOnlyArray<{|bullet: boolean, text: string|}>,
    section: string,
    icon: ?string,
  |}>,
|}

class Loading extends React.Component<{}, {waited: boolean}> {
  state = {waited: false}
  _id: TimeoutID

  componentDidMount() {
    this._id = setTimeout(() => this.setState({waited: true}), 1000)
  }

  componentWillUnmount() {
    clearTimeout(this._id)
  }

  render() {
    return (
      this.state.waited && (
        <Kb.Box2 centerChildren={true} noShrink={true} direction="vertical" gap="medium" style={styles.grow}>
          <Kb.ProgressIndicator style={styles.progress} />
          <Kb.Text type="BodySemibold" style={styles.shrink}>
            Thinking...
          </Kb.Text>
        </Kb.Box2>
      )
    )
  }
}

const validIcon = (s: any) => !!s && !!iconMeta[s]

class Airdrop extends React.Component<Props> {
  componentDidMount() {
    this.props.onLoad()
  }

  render() {
    const p = this.props
    return p.loading ? (
      <Loading />
    ) : (
      <Kb.ScrollView style={styles.scrollView}>
        <Kb.Box2 noShrink={true} direction="vertical" fullWidth={true} gap="medium">
          {p.signedUp ? (
            <Kb.Box2 direction="horizontal" fullWidth={true} style={styles.signedUpHeader} gap="small">
              <Kb.Icon type="icon-stellar-coins-stacked-16" />
              <Kb.Text backgroundMode="Terminal" type="BodySemibold" style={styles.shrink}>
                You’re in!
              </Kb.Text>
            </Kb.Box2>
          ) : (
            <Kb.Box2 direction="horizontal" fullWidth={true} style={styles.header}>
              <Kb.Box2 direction="vertical" centerChildren={true} style={styles.starContainer}>
                <Kb.Icon
                  type={Styles.isMobile ? 'icon-stellar-coins-stacked-16' : 'icon-stellar-coins-flying-48'}
                  style={styles.bigStar}
                />
              </Kb.Box2>
              <Kb.Box2 direction="vertical" gap="small" style={styles.shrink}>
                <Kb.Markdown styleOverride={headerOverride}>{p.headerTitle}</Kb.Markdown>
                <Kb.Markdown styleOverride={bodyOverride}>{p.headerBody}</Kb.Markdown>
                <Kb.Button
                  backgroundMode="Purple"
                  type="PrimaryColoredBackground"
                  label="See if you qualify"
                  onClick={p.onCheckQualify}
                  style={styles.bannerButton}
                />
              </Kb.Box2>
            </Kb.Box2>
          )}
          <Kb.Box2 noShrink={true} direction="vertical" fullWidth={true} style={styles.body} gap="small">
            {p.sections.map(b => (
              <Kb.Box2 key={b.section} direction="horizontal" gap="large" fullWidth={true}>
                <Kb.Box2 direction="vertical" gap="xtiny" alignSelf="flex-start">
                  <Kb.Markdown style={styles.section} styleOverride={sectionOverride}>
                    {b.section}
                  </Kb.Markdown>
                  {b.lines.map(l => (
                    <Kb.Box2 key={l.text} direction="horizontal" fullWidth={true}>
                      {l.bullet && (
                        <Kb.Icon
                          type="iconfont-check"
                          color={Styles.globalColors.green}
                          fontSize={12}
                          style={styles.bullet}
                        />
                      )}
                      <Kb.Markdown styleOverride={sectionBodyOverride}>{l.text}</Kb.Markdown>
                    </Kb.Box2>
                  ))}
                </Kb.Box2>
                {validIcon(b.icon) && <Kb.Icon type={(b.icon: any)} />}
              </Kb.Box2>
            ))}
          </Kb.Box2>
          {p.signedUp ? (
            <Kb.WaitingButton
              type="Danger"
              label="Leave program"
              onClick={p.onReject}
              waitingKey={Constants.airdropWaitingKey}
            />
          ) : (
            <Kb.Button type="PrimaryGreen" label="See if you qualify" onClick={p.onCheckQualify} />
          )}
          <Kb.Box2 direction="horizontal" fullWidth={true} style={styles.friendContainer} gap="large">
            <Kb.Box2 direction="vertical" gap="tiny">
              <Kb.Text type="BodySemibold">Your friends qualify?</Kb.Text>
              <Kb.Text type="Body">
                Tell them to visit{' '}
                <Kb.Text
                  type="BodyPrimaryLink"
                  style={styles.link}
                  onClick={() => openURL('https://keybase.io/airdrop')}
                >
                  https://keybase.io/airdrop
                </Kb.Text>
                .
              </Kb.Text>
            </Kb.Box2>
            <Kb.Icon
              type={Styles.isMobile ? 'icon-stellar-coins-stacked-16' : 'icon-stellar-coins-flying-48'}
              style={styles.friendsStar}
            />
          </Kb.Box2>
        </Kb.Box2>
      </Kb.ScrollView>
    )
  }
}

const headerOverride = {
  paragraph: {
    ...Styles.globalStyles.fontSemibold,
    color: Styles.globalColors.white,
    fontSize: Styles.isMobile ? 20 : 16,
  },
  strong: {...Styles.globalStyles.fontExtrabold},
}
const bodyOverride = {
  paragraph: {
    color: Styles.globalColors.white,
    fontSize: Styles.isMobile ? 16 : 13,
  },
  strong: {...Styles.globalStyles.fontExtrabold},
}
const sectionOverride = {
  paragraph: {
    ...Styles.globalStyles.fontSemibold,
    fontSize: Styles.isMobile ? 18 : 14,
  },
  strong: {...Styles.globalStyles.fontExtrabold},
}
const sectionBodyOverride = {
  paragraph: {fontSize: Styles.isMobile ? 16 : 13},
}

const styles = Styles.styleSheetCreate({
  bannerButton: {alignSelf: 'flex-start'},
  bigStar: Styles.platformStyles({
    isElectron: {height: 80, width: 80},
    isMobile: {height: 20, width: 20},
  }),
  body: {
    paddingLeft: Styles.globalMargins.small,
    paddingRight: Styles.globalMargins.small,
  },
  bullet: {
    marginLeft: Styles.globalMargins.tiny,
    marginRight: Styles.globalMargins.tiny,
  },
  friendContainer: {backgroundColor: Styles.globalColors.lightGrey, padding: Styles.globalMargins.small},
  friendsStar: Styles.platformStyles({
    isElectron: {height: 100, width: 100},
    isMobile: {height: 100, width: 100},
  }),
  grow: {flexGrow: 1},
  header: {
    backgroundColor: Styles.globalColors.purple3,
    padding: Styles.isMobile ? Styles.globalMargins.small : Styles.globalMargins.medium,
  },
  link: {color: Styles.globalColors.purple},
  progress: {
    height: 20,
    width: 20,
  },
  scrollView: {
    height: '100%',
    width: '100%',
  },
  section: {marginBottom: Styles.globalMargins.xxtiny},
  shrink: {flexShrink: 1},
  signedUpHeader: {
    backgroundColor: Styles.globalColors.green,
    flexShrink: 1,
    padding: Styles.globalMargins.tiny,
  },
  starContainer: {width: Styles.isMobile ? 40 : 150},
})

export default (Styles.isMobile ? Kb.HeaderHoc(Airdrop) : Airdrop)
