---
layout: post
title: Solving the Extended Hidden Number Problem 
subtitle: Cracking ECDSA biased nonces using lattices
thumbnail-img: /assets/img/ctfImages/2021/tsg2021/lll-meme.jpeg
share-img: /assets/img/path.jpg
tags: [Cryptography, ECDSA, Biased Nonces, LLL, Lattices, EHNP]
---

![TSG 2021 Writeup](/assets/img/ctfImages/2021/tsg2021/logo.png)

I participated in the University of Tokyo's <a href="https://ctftime.org/event/1431" target="_blank">TSG 2021 CTF</a> event (Sat, 02 Oct. 2021, 15:00 SGT — Sun, 03 Oct. 2021, 15:00 SGT) during the weekend. Even though I am currently still in high school, I was invited to join the National University of Singapore's CTF team, <a href="https://ctftime.org/team/16740" target="_blank">NUSGreyhats</a>, by Diamondroxxx and we ranked 31<sup>st</sup> out of 775 scoring teams.

The reason why I am writing this as a blog post instead of a usual CTF writeup is because I could only solve the beginner's crypto challenge and most of my time was spent solving the ECDSA biased nonce challenge 'Flag Is Win'. However, due to an **incredibly** stupid mistake, me and Diamondroxxx only solved the challenge about 30 minutes after the CTF ended which **really, really sucks**. 

The point of this blog post is to explain both to myself and othes, how to crack the nonce of an ECDSA signature scheme if it does not have uniform random distribution and has low entropy by solving the Extended Hidden Number Problem (EHNP) using lattice reduction techniques.

Below is the writeup for the challenge Flag is Win :

<br/>

<br/>

## Flag is Win

![TSG 2021 Writeup](/assets/img/ctfImages/2021/tsg2021/img1.png)

The server source code provided (written in Ruby) :

```ruby

require 'openssl'
require 'digest'

STDOUT.sync = true

class OpenSSL::PKey::EC::Point
  def xy
    n = to_bn(:uncompressed).to_i
    mask = (1 << group.degree) - 1
    return (n >> group.degree) & mask, n & mask
  end
  alias_method :+, :add
  alias_method :*, :mul
end

class ECDSA
  def initialize
    @curve = OpenSSL::PKey::EC::Group.new('secp256k1')
    @G = @curve.generator
    @n = @curve.order.to_i
    @d = OpenSSL::BN.rand(@curve.degree).to_i
    @Q = @G * @d
  end

  def inv(x)
    x.pow(@n - 2, @n)
  end

  def sign(msg)
    z = Digest::SHA256.hexdigest(msg).hex
    k = OpenSSL::BN.rand(@curve.degree / 3).to_s.unpack1('H*').hex
    x, y = (@G * k).xy

    # We should discourage every evil hacks
    s = (z + x * @d) * inv(k) % @n

    return x, s
  end

  def verify(msg, x, s)
    return false if x % @n == 0 || s % @n == 0
    z = Digest::SHA256.hexdigest(msg).hex

    # ditto
    x2, y2 = (@G * (z * inv(s)) + @Q * (x * inv(s))).xy

    return x == x2
  end
end

ecdsa = ECDSA.new

5.times do
  puts <<~EOS
    1. Sign
    2. Find rule
    3. Exit
  EOS

  print 'choice? '

  case gets.chomp
  when '1'
    x, s = ecdsa.sign('Baba')
    puts 'Baba is:'
    puts "x = #{x}"
    puts "s = #{s}"
  when '2'
    print 'Which rule do you want to know? '; msg = gets.chomp
    print 'x? '; x = gets.to_i
    print 's? '; s = gets.to_i

    if ecdsa.verify(msg, x, s)
      if msg == 'Baba'
        puts 'Baba is you'
      elsif msg == 'Flag'
        puts "Flag is #{ENV['FLAG']}"
      else
        puts 'Not Found :('
      end
    else
      puts 'Invalid :('
    end
  else
    exit
  end
end

puts 'You is defeat.'

```
