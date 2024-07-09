# Copyright 2011 Google Inc. All Rights Reserved.
# Copyright 2023 Wilco Baan Hofman. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Nokia ServiceRouter exec generator."""

import datetime
import collections
from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import summarizer
from itertools import product
from capirca.lib.policy import TranslatePorts

from binascii import crc_hqx

# generic error class
class Error(Exception):
  pass

class NokiaTermPortProtocolError(Error):
  pass


class TcpEstablishedWithNonTcpError(Error):
  pass


class NokiaDuplicateTermError(Error):
  pass


class UnsupportedFilterError(Error):
  pass


class PrecedenceError(Error):
  pass


class NokiaIndentationError(Error):
  pass



class NokiaMultipleTerminatingActionError(Error):
  pass


class Config:
  """Config allows a configuration to be assembled easily.

  Configurations are currently not indented because nokia does not have replace syntax.
  A textual representation of the config can be extracted with str().

  Attributes:
    lines: the text lines of the configuration.
  """

  def __init__(self):
    self.lines = []

  def Append(self, line):
    self.lines.append(line)

  def __str__(self):
    return "\n".join(self.lines)

class Term(aclgenerator.Term):
  """Representation of an individual Nokia entry.

    This is mostly useful for the __str__() method.
  Attributes:
    term: The term object from policy.
    term_type: String indicating type of term, inet, inet6 icmp etc.
      interface e.g. INGRESS.
  """
  _PLATFORM = 'nokia'
  _DEFAULT_INDENT = 12
  ACTIONS = {'accept': 'accept',
             'deny': 'drop',
             'next': 'ignore-match',
             'reject': 'drop', # 'forward next-hop nh-ip address 192.0.2.42', # There is no reject except if a nexthop is unreachable
             'port-mirror': 'forward next-hop interface-name'}

  # the following lookup table is used to map between the various types of
  # filters the juniper generator can render.  As new differences are
  # encountered, they should be added to this table.  Accessing members
  # of this table looks like:
  #  self._TERM_TYPE('inet').get('saddr') -> 'source-prefix-list'
  #
  # it's critical that the members of each filter type be the same, that is
  # to say that if _TERM_TYPE.get('inet').get('foo') returns something,
  # _TERM_TYPE.get('inet6').get('foo') must return the inet6 equivalent.
  _TERM_TYPE = {'inet': {'addr': 'ip ip-prefix-list',
                         'saddr': 'src-ip ip-prefix-list',
                         'daddr': 'dst-ip ip-prefix-list',
                         'protocol': 'protocol',
                         'protocol-list': 'protocol-list'},
                'inet6': {'addr': 'ip ipv6-prefix-list',
                          'saddr': 'src-ip ipv6-prefix-list',
                          'daddr': 'dst-ip ipv6-prefix-list',
                          'protocol': 'next-header',
                          'protocol-list': 'next-header-list'},
               }
  _PROTOCOL_REV_MAP = {
                         1: 'icmp',
                         2: 'igmp',
                         4: 'ip',
                         6: 'tcp',
                         8: 'egp',
                         9: 'igp',
                        17: 'udp',
                        27: 'rdp',
                        41: 'ipv6',
                        43: 'ipv6-route',
                        44: 'ipv6-frag',
                        45: 'idrp',
                        46: 'rsvp',
                        47: 'gre',
                        58: 'ipv6-icmp',
                        59: 'ipv6-no-nxt',
                        60: 'ipv6-opts',
                        80: 'iso-ip',
                        88: 'eigrp',
                        89: 'ospf-igp',
                        97: 'etherip',
                        98: 'encap',
                       102: 'pnni',
                       103: 'pim',
                       112: 'vrrp',
                       115: 'l2tp',
                       118: 'stp',
                       112: 'vrrp',
                       123: 'ptp',
                       124: 'isis',
                       126: 'crtp',
                       127: 'crudp',
                       132: 'sctp',
                      }

  def __init__(self, term, parent, term_type, filter_name, entry_number):
    super().__init__(term)
    self.term = term
    self.parent = parent
    self.term_type = term_type
    self.filter_name = filter_name
    self.entry_number = entry_number
    self.entry_offset = 0
    self.config = Config()
    self.match_criteria = []
    self.entry_options = []
    self.extra_actions = []
    self.context = ""


  def _write_entry(self, prefix=None, 
                         srcprefix=None,
                         dstprefix=None,
                         port=None,
                         srcport=None,
                         dstport=None,
                         icmp_type=None):
    subcontext = '/configure %s entry %d' % (self.context, self.entry_number + self.entry_offset)
    description = []
    if prefix:
      description.append("prefix %s" % prefix)

    if srcprefix:
      description.append("src %s" % srcprefix)

    if srcport:
      description.append("srcport %s" % srcport)

    if dstprefix:
      description.append("dst %s" % dstprefix)

    if dstport:
      description.append("dstport %s" % dstport)

    if port:
      description.append("port %s" % port)

    if icmp_type:
      description.append("icmp type %s" % icmp_type)

    config = self.config
    description = ("term %s (%s)" % (self.term.name, " ".join(description)))[:80]
    config.Append(subcontext + " description \"%s\"" % description)
    if prefix:
      config.Append(subcontext + ' match %s %s' % (self.family_keywords['addr'], prefix[:32]))
    if srcprefix:
      config.Append(subcontext + ' match %s %s' % (self.family_keywords['saddr'], srcprefix[:32]))
    if dstprefix:
      config.Append(subcontext + ' match %s %s' % (self.family_keywords['daddr'], dstprefix[:32]))

    if icmp_type:
      config.Append(subcontext + ' match icmp type %s' % icmp_type)
    if port:
      config.Append(subcontext + ' match port port-list %s' % port)
    if srcport:
      config.Append(subcontext + ' match src-port port-list %s' % srcport)
    if dstport:
      config.Append(subcontext + ' match dst-port port-list %s' % dstport)
    for criterium in self.match_criteria:
      config.Append(subcontext + ' match %s' % criterium)
    for option in self.entry_options:
      config.Append(subcontext + ' %s' % option)

    # FIXME full action matching
    config.Append(subcontext + ' action %s' % (self.ACTIONS[self.term.action[0]]))
    self.entry_offset += 1

  # TODO(pmoody): get rid of all of the default string concatenation here.
  #  eg, indent(8) + 'foo;' -> '%s%s;' % (indent(8), 'foo'). pyglint likes this
  #  more.
  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    term_af = self.AF_MAP.get(self.term_type)
    # term name

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.term_type == 'inet6' and 'icmp' in self.term.protocol) or
        (self.term_type == 'inet' and ('icmpv6' in self.term.protocol or
                                       'icmp6' in self.term.protocol))):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(
          term=self.term.name,
          proto=', '.join(self.term.protocol),
          af=self.term_type))
      return ''

    config = self.config
    self.context = 'filter %s %s' % ("ip-filter" if term_af == 4 else "ipv6-filter", self.filter_name)
    match_criteria = self.match_criteria
    entry_options = self.entry_options
    extra_actions = self.extra_actions

    # Helper for per-address-family keywords.
    self.family_keywords = self._TERM_TYPE.get(self.term_type)

    # option
    # this is going to be a little ugly b/c there are a few little messed
    # up options we can deal with.
    if self.term.option:
      for opt in [str(x) for x in self.term.option]:
        # there should be a better way to search the array of protocols
        if opt.startswith('sample'):
          entry_options.append('filter-sample')

        # only append tcp-established for option established when
        # tcp is the only protocol, otherwise other protos break on juniper
        elif opt.startswith('established'):
          if self.term.protocol == ['tcp']:
            if 'tcp-established' not in match_criteria:
              match_criteria.append('tcp-established')

        # if tcp-established specified, but more than just tcp is included
        # in the protocols, raise an error
        elif opt.startswith('tcp-established'):
          if self.term.protocol == ['tcp']:
            if 'tcp-established' not in match_criteria:
              match_criteria.append('tcp-established')
          else:
            raise TcpEstablishedWithNonTcpError(
                'tcp-established can only be used with tcp protocol in term %s'
                % self.term.name)
        elif opt.startswith('rst'):
          match_criteria.append('tcp-flags rst true')
        elif opt.startswith('initial') and 'tcp' in self.term.protocol:
          match_criteria.append('tcp-flags syn true ack false fin false rst false')
        elif opt.startswith('first-fragment'):
          match_criteria.append('fragment first-only')
        elif opt.startswith('is-fragment'):
          match_criteria.append('fragment true')

        # we don't have a special way of dealing with this, so we output it and
        # hope the user knows what they're doing.
        else:
          match_criteria.append(opt)

    # if the term is inactive we have to set the prefix
    if self.term.inactive:
      return ''



    entry_offset = 0

    # Only generate ttl if inet, inet6 uses hop-limit instead.
    if self.term.ttl and self.term_type == 'inet':
      match_criteria.append('ttl lt %s;' % self.term.ttl)
    # Only generate a hop-limit if inet6, inet4 has no hop-limit.
    if self.term.hop_limit and self.term_type == 'inet6':
      match_criteria.append('hop-limit lt %s' % (self.term.hop_limit))

    # ICMP code (With only single icmp type hopefully)
    if self.term.icmp_code:
      match_criteria.append('icmp code %s' % self.term.icmp_code)


    # DSCP Match
    if self.term.dscp_match:
      match_criteria.append('dscp %s' % ' '.join(self.term.dscp_match))


    # FIXME Make logic for forward-when, discard-when and rate-limit with bit-patterns (flexible-match-mask)
    # FIXME Juniper flexible-match verbatim bullshit, make something that's actually supported in juniper and nokia
    if self.term.flexible_match_range:
      config.Append('flexible-match-range {')
      for fm_opt in self.term.flexible_match_range:
        config.Append('%s %s;' % (fm_opt[0], fm_opt[1]))

    #
    # Workaround Nokia's for 1 prefix list per entry
    # Annoyingly on nokia, one entry can have exactly one prefix list, so this requires a split
    # The upside is of course getting many many counters
    #
    address = self.term.GetAddressOfVersion('address', term_af)
    address_ex = self.term.GetAddressOfVersion('address_exclude', term_af)
    src_addr = self.term.GetAddressOfVersion('source_address', term_af)
    src_addr_ex = self.term.GetAddressOfVersion('source_address_exclude', term_af)
    dst_addr = self.term.GetAddressOfVersion('destination_address', term_af)
    dst_addr_ex = self.term.GetAddressOfVersion('destination_address_exclude', term_af)

    address_prefixlists = sorted(set([x.parent_token for x in address]))
    src_prefixlists = sorted(set([x.parent_token for x in src_addr]))
    dst_prefixlists = sorted(set([x.parent_token for x in dst_addr]))

    # Workaround for Nokia not being able to do prefix-list .. exclude in an entry. Refer to the prefix-list for the term
    if len(address_ex):
      prefixlist_basename = ("%s-%s" % (self.filter_name, self.term.name))[:32-len("-addr")]
      prefixlist_name = "%s%s" % (prefixlist_basename, "-addr")
      address_prefixlists = [ prefixlist_name ]
    if len(src_addr_ex):
      prefixlist_basename = ("%s-%s" % (self.filter_name, self.term.name))[:32-len("-src")]
      prefixlist_name = "%s%s" % (prefixlist_basename, "-src")
      src_prefixlists = [ prefixlist_name ]
    if len(dst_addr_ex):
      prefixlist_basename = ("%s-%s" % (self.filter_name, self.term.name))[:32-len("-dst")]
      prefixlist_name = "%s%s" % (prefixlist_basename, "-dst")
      dst_prefixlists = [ prefixlist_name ]


    icmp_types = []
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, self.term_type)

    # Add the non-lookup prefixes to the source/dest prefix lists
    if self.term.source_prefix:
      src_prefixlists.extend(self.term.source_prefix)

    if self.term.destination_prefix:
      dst_prefixlists.extend(self.term.destination_prefix)

    # port name mapping to tcp/udp-specific port lists
    port_names = []
    source_port_names = []
    destination_port_names = []
    for protocol in self.term.protocol:
      port_names.extend(["%s-%s" % (x, protocol) for x in self.term.port_names])
      source_port_names.extend(["%s-%s" % (x, protocol) for x in self.term.source_port_names])
      destination_port_names.extend(["%s-%s" % (x, protocol) for x in self.term.destination_port_names])

    # Remove empty protocols (for instance tcp where there is no tcp in the ports)
    port_names = [x for x in port_names if x in self.parent.portlists]
    source_port_names = [x for x in source_port_names if x in self.parent.portlists]
    destination_port_names = [x for x in destination_port_names if x in self.parent.portlists]

    # protocol
    if self.term.protocol:
      # Nokia supports only one protocol, but to get around this, they added
      # a hack for tcp + udp as one protocol name 'tcp-udp', it saves on entries.
      protocol = self.term.protocol
      if set(protocol) == {'tcp', 'udp'}:
        protocol = ['tcp-udp']

      # If we still have one protocol left, add it as match criteria
      if len(protocol) == 1:
        protocol = protocol[0]
        if protocol != 'tcp-udp':
          if self.PROTO_MAP[protocol] in self._PROTOCOL_REV_MAP:
            protocol = self._PROTOCOL_REV_MAP[self.PROTO_MAP[protocol]]
          else:
            protocol = self.PROTO_MAP[protocol]

        match_criteria.append("%s %s" % (self.family_keywords['protocol'], protocol))
      # If we have multiple protocols, create and reference a protocol list
      else:
        # We're already warning for the 32 char limit
        match_criteria.append("%s %s" % (self.family_keywords['protocol-list'], ("%s_%s" % (self.filter_name, self.term.name))[:32]))

    # [None] is the neutral list (1) for itertools.product()
    if not len(address_prefixlists):
      address_prefixlists = [None]
    if not len(src_prefixlists):
      src_prefixlists = [None]
    if not len(dst_prefixlists):
      dst_prefixlists = [None]
    if not len(icmp_types):
      icmp_types = [None]
    if not len(port_names):
      port_names = [None]
    if not len(source_port_names):
      source_port_names = [None]
    if not len(destination_port_names):
      destination_port_names = [None]

    # Create a full product of all lists
    for manytuple in product(address_prefixlists,
                             src_prefixlists,
                             dst_prefixlists,
                             port_names,
                             source_port_names,
                             destination_port_names,
                             icmp_types):
      self._write_entry(*manytuple)

    # FIXME implement log facility (numeric)
    # FIXME implement non-named rate-limit facility rate-limit pir / pps-pir


    # comment / annotation
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    if self.term.comment:
      comment = "\n".join(self.term.comment).replace("\n", "\\n")
      config.Append("annotate \"%s\" cli-path %s entry %d" % (comment, self.context, self.entry_number))


    return str(config)



class Nokia(aclgenerator.ACLGenerator):
  """Nokia SR filter rendering class.

    This class takes a policy object and renders the output into a syntax
    which is understood by Nokia SR routers.

  Attributes:
    pol: policy.Policy object
  """

  _PLATFORM = 'nokia'
  _DEFAULT_PROTOCOL = 'ip'
  _DEFAULT_INDENT = 12
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
  _TERM = Term
  SUFFIX = '.nokiasr'
  _AF_MAP = {'inet': (4,),
             'inet6': (6,),
             'mixed': (4, 6)}

  def __init__(self, pol, exp_info):
    self.prefixlists = collections.OrderedDict()
    self.prefixlists_ex = collections.OrderedDict()
    self.portlists = collections.OrderedDict()
    self.protocollists = collections.OrderedDict()
    self.entry_number = 0
    super().__init__(pol, exp_info)

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {'address',
                         'restrict_address_family',
                         'counter',
                         'destination_prefix',
                         'dscp_match',
                         'dscp_set',
                         'ether_type',
                         'flexible_match_range',
                         'hop_limit',
                         'icmp_code',
                         'logging',
                         'loss_priority',
                         'next_ip',
                         'owner',
                         'policer',
                         'port',
                         'port_mirror',
                         'qos',
                         'routing_instance',
                         'source_prefix',
                         'traffic_class_count',
                         'ttl',}
    supported_sub_tokens.update({
        'option': {
            'established',
            'first-fragment',
            'is-fragment',
            # TODO(sneakywombat): add all options to lex.
            '.*',  # make ArbitraryOptions work, yolo.
            'sample',
            'tcp-established',
            'tcp-initial',
            'inactive'}
         })
    return supported_tokens, supported_sub_tokens

  def _BuildProtocolList(self, protocollist, filter_name, term):
    new_list = []
    for protocol in protocollist:
      # Convert to numeric if possible
      if self._TERM.PROTO_MAP[protocol] in self._TERM._PROTOCOL_REV_MAP:
        protocol = self._TERM._PROTOCOL_REV_MAP[self._TERM.PROTO_MAP[protocol]]
      else:
        protocol = self._TERM.PROTO_MAP[protocol]
      new_list.append(protocol)

    self.protocollists[("%s_%s" % (filter_name, term.name))[:32]] = new_list

  def _BuildPortList(self, portlist, protocol, term_name):
    translatedlist = TranslatePorts([portlist], [protocol], term_name)
    if not translatedlist:
      return

    self.portlists[portlist + "-" + protocol] = translatedlist


  def _BuildNamedPrefixList(self, name, address, exclude=False):
    """Create the prefix list configuration entries.

    Args:
      address: a naming library address object
    """
    if name not in self.prefixlists:
      self.prefixlists[name] = []
    if name not in self.prefixlists_ex:
      self.prefixlists_ex[name] = []

    if exclude:
      if not address in self.prefixlists_ex[name]:
        self.prefixlists_ex[name].append(address)
    else:
      if not address in self.prefixlists[name]:
        self.prefixlists[name].append(address)

  def _SortPrefixListNumCheck(self, item):
    """Used to give a natural order to the list of acl entries.

    Args:
      item: string of the address book entry name

    Returns:
      returns the characters and number
    """

    item_list = item.split('_')
    num = item_list.pop(-1)
    if isinstance(item_list[-1], int):
      set_number = item_list.pop(-1)
      num = int(set_number) * 1000 + int(num)
    alpha = '_'.join(item_list)
    if num:
      return (alpha, int(num))
    return (alpha, 0)

  def _PopulatePrefixList(self, filter_type, filter_name, term_name, addresses, excludes, suffix):
    valid_addrs = []
    valid_exclude = []
    for addr in addresses:
      if addr.version in self._AF_MAP[filter_type]:
        valid_addrs.append(addr)
    for addr in excludes:
      if addr.version in self._AF_MAP[filter_type]:
        valid_exclude.append(addr)

    if not len(valid_addrs) and not len(valid_exclude):
      logging.warning(
        'WARNING: Term %s has 0 valid source IPs, skipping.', term_name)
      return

    if len(valid_exclude):
      prefixlist_basename = ("%s-%s" % (filter_name, term_name))[:32-len(suffix)]
      prefixlist_name = "%s%s" % (prefixlist_basename, suffix)

    if not len(valid_addrs) and filter_type == "inet":
      self._BuildNamedPrefixList(prefixlist_name, nacaddr.IPv4("0.0.0.0/0", comment="any"), exclude=False)
    if not len(valid_addrs) and filter_type == "inet6":
      self._BuildNamedPrefixList(prefixlist_name, nacaddr.IPv6("2000::/3", comment="any"), exclude=False)

    if len(valid_exclude):
      for addr in valid_addrs:
        self._BuildNamedPrefixList(prefixlist_name, addr, exclude=False)
    else:
      for addr in valid_addrs:
        self._BuildNamedPrefixList(addr.parent_token, addr, exclude=False)
    for addr in valid_exclude:
      self._BuildNamedPrefixList(prefixlist_name, addr, exclude=True)

  def _TranslatePolicy(self, pol, exp_info):
    self.nokia_filters = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)


      # default to inet4 filters
      filter_type = 'inet'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      if filter_type == 'mixed':
        filter_types_to_process = ['inet', 'inet6']
      else:
        filter_types_to_process = [filter_type]

      scope = "template"
      if len(filter_options) > 2:
        scope = filter_options[2]

      chain_to_system = not "no-chain-to-system" in filter_options[2:]

      if scope == "system":
        chain_to_system = False

      for filter_type in filter_types_to_process:

        term_names = set()
        new_terms = []
        for term in terms:

          # Ignore if the term is for a different AF
          if term.restrict_address_family and term.restrict_address_family != filter_type:
            continue

          # if inactive is set, deactivate the term and remove the option.
          if 'inactive' in term.option:
            term.inactive = True
            term.option.remove('inactive')

          term.name = self.FixTermLength(term.name)

          if term.name in term_names:
            raise NokiaDuplicateTermError('You have multiple terms named: %s' %
                                            term.name)
          term_names.add(term.name)

          term = self.FixHighPorts(term, af=filter_type)
          if not term:
            continue

          if term.expiration:
            if term.expiration <= exp_info_date:
              logging.info('INFO: Term %s in policy %s expires '
                          'in less than two weeks.', term.name, filter_name)
            if term.expiration <= current_date:
              logging.warning('WARNING: Term %s in policy %s is expired and '
                              'will not be rendered.', term.name, filter_name)
              continue

          # Filter address based on filter_type & add to prefix-list
          if term.address or term.address_exclude:
            self._PopulatePrefixList(filter_type, filter_name, term.name, term.address, term.address_exclude, "-addr")

          # Filter source_address based on filter_type & add to prefix-list
          if term.source_address or term.source_address_exclude:
            self._PopulatePrefixList(filter_type, filter_name, term.name, term.source_address, term.source_address_exclude, "-src")

          # Filter destination_address based on filter_type & add to prefix-list
          if term.destination_address or term.destination_address_exclude:
            self._PopulatePrefixList(filter_type, filter_name, term.name, term.destination_address, term.destination_address_exclude, "-dst")

          if term.port_names:
            for portlist in term.port_names:
              for protocol in term.protocol:
                self._BuildPortList(portlist, protocol, term.name)
          if term.source_port_names:
            for portlist in term.source_port_names:
              for protocol in term.protocol:
                self._BuildPortList(portlist, protocol, term.name)
          if term.destination_port_names:
            for portlist in term.destination_port_names:
              for protocol in term.protocol:
                self._BuildPortList(portlist, protocol, term.name)

          if len(term.protocol) > 1 and set(term.protocol) != {'tcp', 'udp'}:
            self._BuildProtocolList(term.protocol, filter_name, term)


          self.entry_number += 10000
          new_terms.append(self._TERM(term, self, filter_type, filter_name, self.entry_number))

        self.nokia_filters.append((header, filter_name, filter_type, scope, chain_to_system,
                                     new_terms))

  def _GenerateProtocolLists(self, config):
    names = sorted(self.protocollists.keys())
    for name in names:
      if len(name) > 32:
        logging.warning('WARNING: Protocol list name "%s"  is too long and will be cropped to "%s"' % (name[:32]))

      config.Append('delete filter match-list protocol-list %s' % name[:32])

      for protocol in self.protocollists[name]:
        config.Append("/configure filter match-list protocol-list %s protocol %s" % (name[:32], protocol))

  def _GeneratePortLists(self, config):
    """Creates filter match-list port-list."""

    names = sorted(self.portlists.keys())
    for name in names:
      if len(name) > 32:
        logging.warning('WARNING: Port list name "%s"  is too long and will be cropped to "%s"' % (name, name[:32]))

      config.Append('delete filter match-list port-list %s' % name[:32])
      for port in self.portlists[name]:
        if port[0] != port[1]:
          config.Append("/configure filter match-list port-list %s range start %d end %d" % (name[:32], port[0],port[1]))
        else:
          config.Append("/configure filter match-list port-list %s port %s" % (name[:32], port[0]))

  def _GeneratePrefixLists(self, config):
    """Creates filter match-list ip(v6)?-prefix-list."""

    names = sorted(self.prefixlists.keys())
    for name in names:
      if len(name) > 32:
        logging.warning('WARNING: Prefix list name "%s"  is too long and will be cropped to "%s"' % (name, name[:32]))

      # Do not delete prefix lists if we don't recreate it! Necessary for non-mixed filters
      have_ipv4 = False
      have_ipv6 = False
      for ip in self.prefixlists[name]:
        if ip.version == 6:
          have_ipv6 = True
        else:
          have_ipv4 = True

      if have_ipv4:
        config.Append('delete filter match-list ip-prefix-list %s' % name[:32])
      if have_ipv6:
        config.Append('delete filter match-list ipv6-prefix-list %s' % name[:32])

      ips = nacaddr.SortAddrList(self.prefixlists[name])
      ips = nacaddr.CollapseAddrList(ips)
      exclude_ips = nacaddr.SortAddrList(self.prefixlists_ex[name])
      exclude_ips = nacaddr.CollapseAddrList(exclude_ips)
      self.prefixlists[name] = ips
      self.prefixlists_ex[name] = exclude_ips

      # Write out prefix lists
      for ip in self.prefixlists[name]:
        # Nokia workaround for 0.0.0.0/0 in prefix list, expands to 2 /31s, IPv6 works with 2000::/3
        if str(ip) == "0.0.0.0/0":
          write_ips = [ "0.0.0.0/1", "128.0.0.0/1" ]
        else:
          write_ips = [ str(ip) ]

        for write_ip in write_ips:
          cli_path = "filter match-list %s %s prefix %s" % ("ipv6-prefix-list" if ip.version == 6 else "ip-prefix-list", name[:32], write_ip)
          config.Append('/configure %s' % cli_path)
          if ip.text:
            config.Append('annotate "%s" cli-path %s' % (ip.text.replace("\n", "\\n"), cli_path))

      # Write out excludes
      for ip in self.prefixlists_ex[name]:
        cli_path = "filter match-list %s %s prefix-exclude %s" % ("ipv6-prefix-list" if ip.version == 6 else "ip-prefix-list", name[:32], str(ip))
        config.Append('/configure %s' % cli_path)
        if ip.text:
          config.Append('annotate "%s" cli-path %s' % (ip.text.replace("\n", "\\n"), cli_path))

  def __str__(self):
    config = Config()
    self._GenerateProtocolLists(config)
    self._GeneratePrefixLists(config)
    self._GeneratePortLists(config)

    for (header, filter_name, filter_type, scope, chain_to_system, terms
        ) in self.nokia_filters:

      cli_path = 'filter %s %s' % ("ip-filter" if filter_type == 'inet' else 'ipv6-filter', filter_name )
      config.Append('delete %s' % cli_path)

      config.Append('/configure %s scope %s' % (cli_path, scope))
      config.Append('/configure %s chain-to-system-filter %s' % (cli_path, "true" if chain_to_system else "false"))

      # FIXME filter-id has collisions n in 2^16 where n is number of filters
      config.Append('/configure %s filter-id %d' % (cli_path, crc_hqx(filter_name.encode('utf-8'),0)))



      for comment in header.comment:
        for line in comment.split('\n'):
          config.Append('annotate "%s" cli-path %s' % (line.replace("\n", "\\n"), cli_path))

      config.entry_number = 0
      for term in terms:
        term_str = str(term)
        if term_str:
          config.Append(term_str)


    return str(config) + '\n'
