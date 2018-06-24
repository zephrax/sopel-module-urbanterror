# coding=utf-8
"""UrbanTerror server info"""
# Author: zephrax http://kernelpanic.com.ar
from __future__ import unicode_literals, absolute_import, print_function, division

from sopel import web
from sopel.module import commands
from sopel.logger import get_logger
from sopel.config.types import StaticSection, ValidatedAttribute, ListAttribute

import socket
import re

LOGGER = get_logger(__name__)


class Player(object):
    """
    Player class
    """
    def __init__(self, num, name, frags, ping, address=None, bot=-1):
        """
        create a new instance of Player
        """
        self.num = num
        self.name = name
        self.frags = frags
        self.ping = ping
        self.address = address
        self.bot = bot

    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)


class PyQuake3(object):
    """
    PyQuake3 class
    """
    packet_prefix = b'\xff' * 4
    player_reo = re.compile(r'^(\d+) (\d+) "(.*)"')

    rcon_password = None
    port = None
    address = None
    players = None
    values = None

    def __init__(self, server, rcon_password=''):
        """
        create a new instance of PyQuake3
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.set_server(server)
        self.set_rcon_password(rcon_password)

    def set_server(self, server):
        """
        set IP address and port and connect to socket
        """
        try:
            self.address, self.port = server.split(':')
        except Exception:
            raise ValueError('Server address format must be: "address:port"')
        self.port = int(self.port)
        self.sock.connect((self.address, self.port))

    def get_address(self):
        """
        get IP address and port
        """
        return '%s:%s' % (self.address, self.port)

    def set_rcon_password(self, rcon_password):
        """
        set RCON password
        """
        self.rcon_password = rcon_password

    def send_packet(self, data):
        """
        send packet
        """
        base = b''
        self.sock.send(base.join([self.packet_prefix, data.encode(), b'\n']))
        # self.sock.send('{}{}\n'.format(self.packet_prefix, data).encode())

    def recv(self, timeout=1):
        """
        receive packets
        """
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(8192)
        except Exception as err:
            raise Exception('Error receiving the packet: %s' % err[1])

    def command(self, cmd, timeout=1, retries=5):
        """
        send command and receive response
        """
        while retries:
            self.send_packet(cmd)
            try:
                data = self.recv(timeout)
            except Exception:
                data = None
            if data:
                return self.parse_packet(data)
            retries -= 1
        raise Exception('Server response timed out')

    def rcon(self, cmd):
        """
        send RCON command
        """
        r_cmd = self.command('rcon "{}" {}'.format(self.rcon_password, cmd))
        if r_cmd[1] == 'No rconpassword set on the server.\n' or r_cmd[1] == 'Bad rconpassword.\n':
            raise Exception(r_cmd[1][:-1])
        return r_cmd

    def parse_packet(self, data):
        """
        parse the received packet
        """
        if data.find(self.packet_prefix) != 0:
            raise Exception('Malformed packet')

        first_line_length = data.find(b'\n')
        if first_line_length == -1:
            raise Exception('Malformed packet')

        response_type = data[len(self.packet_prefix):first_line_length].decode()
        response_data = data[first_line_length + 1:].decode()
        return response_type, response_data

    def parse_status(self, data):
        """
        parse the response message and return a list
        """
        split = data[1:].split('\\')
        values = dict(zip(split[::2], split[1::2]))
        # if there are \n's in one of the values, it's the list of players
        for var, val in values.items():
            pos = val.find('\n')
            if pos == -1:
                continue
            split = val.split('\n', 1)
            values[var] = split[0]
            self.parse_players(split[1])
        return values

    def parse_players(self, data):
        """
        parse player information - name, frags and ping
        """
        self.players = []
        for player in data.split('\n'):
            if not player:
                continue
            match = self.player_reo.match(player)
            if not match:
                print('couldnt match {}'.format(player))
                continue
            frags, ping, name = match.groups()
            self.players.append(Player(1, name, frags, ping))

    def update(self):
        """
        get status
        """
        data = self.command('getstatus')[1]
        self.values = self.parse_status(data)

    def rcon_update(self):
        """
        perform RCON status update
        """
        data = self.rcon('status')[1]
        lines = data.split(b'\n')

        players = lines[3:]
        self.players = []
        for ply in players:
            while ply.find('  ') != -1:
                ply = ply.replace('  ', ' ')
            while ply.find(' ') == 0:
                ply = ply[1:]
            if ply == '':
                continue
            ply = ply.split(' ')
            try:
                self.players.append(Player(int(ply[0]), ply[3], int(ply[1]), int(ply[2]), ply[5]))
            except (IndexError, ValueError):
                continue


class UrbanTerrorSection(StaticSection):
    """UrbanTerror server host. Default to localhost."""
    server_host = ValidatedAttribute('server_host', str, default='localhost')
    """UrbanTerror server port. Default to 27960."""
    server_port = ValidatedAttribute('server_port', int, default=27960)
    """UrbanTerror server rcon password."""
    rcon_password = ValidatedAttribute('rcon_password', str)


def configure(config):
    config.define_section('urbanterror', UrbanTerrorSection)
    config.urbanterror.configure_setting(
        'server_host',
        "UrbanTerror server hostname or ip.",
    )
    config.urbanterror.configure_setting(
        'server_port',
        'UrbanTerror server port.',
    )
    config.urbanterror.configure_setting(
        'rcon_password',
        'UrbanTerror rcon password.',
    )


def setup(bot):
    bot.config.define_section('urbanterror', UrbanTerrorSection)


@commands('ut')
def ut(bot, trigger):
    """UrbanTerror server stats"""
    try:
        ut_cfg = bot.config.urbanterror
        UT = PyQuake3(server='{}:{}'.format(ut_cfg.server_host, ut_cfg.server_port), rcon_password=ut_cfg.rcon_password)

        UT.update()

        bot.say('Server: {} ({}) | Map: {} | Players ({}) {}'.format(
            UT.values['sv_hostname'],
            UT.get_address(),
            UT.values['mapname'],
            len(UT.players),
            [gamer.name for gamer in UT.players]))
    except Exception as err:
        LOGGER.debug('Internal Error. {}'.format(err))
