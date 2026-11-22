from hardaudit.sshd import effective, parse_sshd_config


def test_missing_config_means_sshd_not_installed(make_root):
    assert parse_sshd_config(make_root({})) is None


def test_first_value_wins(make_root):
    ctx = make_root({"/etc/ssh/sshd_config": "PermitRootLogin no\nPermitRootLogin yes\n"})
    assert parse_sshd_config(ctx)["permitrootlogin"] == "no"


def test_dropin_included_at_top_overrides_main_file(make_root):
    ctx = make_root(
        {
            "/etc/ssh/sshd_config": """
                Include /etc/ssh/sshd_config.d/*.conf
                PasswordAuthentication no
            """,
            "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
        }
    )
    assert parse_sshd_config(ctx)["passwordauthentication"] == "yes"


def test_dropins_are_read_in_alphabetical_order(make_root):
    ctx = make_root(
        {
            "/etc/ssh/sshd_config": "Include sshd_config.d/*.conf\n",  # relative to /etc/ssh
            "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
            "/etc/ssh/sshd_config.d/00-hardening.conf": "PasswordAuthentication no\n",
        }
    )
    assert parse_sshd_config(ctx)["passwordauthentication"] == "no"


def test_match_block_is_ignored(make_root):
    ctx = make_root(
        {
            "/etc/ssh/sshd_config": """
                X11Forwarding no
                Match User deploy
                    PermitRootLogin yes
            """
        }
    )
    settings = parse_sshd_config(ctx)
    assert settings["x11forwarding"] == "no"
    assert "permitrootlogin" not in settings


def test_case_insensitive_keys_equals_syntax_and_comments(make_root):
    ctx = make_root({"/etc/ssh/sshd_config": "# PermitRootLogin yes\npermitrootlogin=No\n"})
    assert effective(parse_sshd_config(ctx), "permitrootlogin") == ("no", False)


def test_defaults_when_keyword_absent(make_root):
    ctx = make_root({"/etc/ssh/sshd_config": ""})
    assert effective(parse_sshd_config(ctx), "permitrootlogin") == ("prohibit-password", True)
