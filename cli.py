#!/usr/bin/env python3

import click
from lib.sw import Switch, full_ip


@click.group()
@click.argument('ip')
@click.pass_context
def cli(ctx, ip):
    try:
        ctx.obj = Switch(full_ip(ip))
    except Switch.UnavailableError as e:
        exit(e)


@cli.command()
@click.pass_context
@click.option('--full', is_flag=True, help='Show additional info.')
def show(ctx, full):
    """Print short switch description"""
    print(ctx.obj.show(full=full))


@cli.command()
@click.pass_context
def connect(ctx):
    """Interact with switch via telnet"""
    ctx.obj.interact()


@cli.command(context_settings=dict(
    ignore_unknown_options=True,
    allow_extra_args=True,
))
@click.pass_context
@click.argument('arg')
@click.option('--file', is_flag=True, help='Use template file.')
def send(ctx, arg, file):
    """Send CMD to switch via telnet"""
    if file:
        # parse extra params for template
        params = dict()
        from ast import literal_eval
        for item in ctx.args:
            p = item.split('=')
            params[p[0]] = literal_eval(p[1])
        print(ctx.obj.send(template=arg, **params))
    else:
        print(ctx.obj.send(commands=arg))


@cli.command()
@click.pass_context
@click.argument('oid')
def snmp(ctx, oid):
    """SNMP get OID from switch"""
    print(ctx.obj.get_oid(oid))


cli()
