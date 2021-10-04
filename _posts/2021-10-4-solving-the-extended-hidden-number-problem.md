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

Looking at the source code, our task is pretty straightforward. When connecting to the server, we are given 5 tries. In each try, we can either sign the word 'Baba' using ECDSA, provide a signature for a given message or exit the session. A standard curve `secp256k1` is used. Obviously we would have to see what is going on with the signing mechanism used here.

<br/>

### ECDSA Recap

Remember that in elliptic curve cryptography, first a random number `d` is used as the private key by multiplying the generator or base point `d` times to reach some final public point `Q`.

Here is how to sign a message *m* using the private key IN ECDSA :

1. Hash the message: \\( h = SHA256(m) \\)
2. Sample a random nonce: \\( k = n \qquad \qquad (n \in \mathbb{Z}^+) \\)
3. Exponentiate by the nonce: \\( r = x_1 \mod n \\)
4. Reduce the x-coordinate mod the group order: $ r = x_1 \mod n $
5. Complete the signature: \\( s = k^{-1} (h + r d) \mod n \\)
6. Signature is: \\( \sigma = (r, s) \\)

<BR/>

### Signature Generation 

Looking at the `sign` function, we can see that the secret nonce `k` is generated really weirdly. To quote rkm0959's writeup for the <a href="https://rkm0959.tistory.com/232?category=765103" target="_blank">H1 challenge</a> in Google CTF 2021, "The ECDSA nonce is yelling loudly at us to attack it which we obviously have to do." Lmao

Usually the `k` should be a uniformally distributed random number however there is very low entropy over here. Note that while `OpenSSL::BN.rand(@curve.degree / 3)` does generate a large random 85 bit number, by appending `.to_s.unpack1('H*')`, a 3 is inserted to the left of every digit of this random number. The image below demonstrates this (the first value is the random number while the second is the number with the `.to_s.unpack1('H*')` added) :

![TSG 2021 Writeup](/assets/img/ctfImages/2021/tsg2021/img2.png)

After that this number is converted to hexadecimal. Wow! So effectively only half of the bits of the nonce have entropy. That is very bad to say the least......

<br/>


### Creating a Lattice

Firstly, we would have to come up with a precise mathematical expression for the nonce. Suppose that we consider the digits of `k` where \\((0 \leq n \leq 9 )\\).    

$$ k = \quad 3 \ n_{25} \quad 3 \ n_{24} \quad 3 \ n_{23} \quad .... \quad 3 \ n_2 \quad 3 \ n_1 \quad 3 \ n_0 $$

We can rewrite this as a mix of binary and the unknown digits \\( n \\) where: 

$$ k = \quad 0011 \ n_{25} \quad 0011 \ x_{24} \quad 0011 \ x_{23} \quad .... \quad 0011 \ x_2 \quad 0011 \ x_1 \quad 3 \ x_0 $$

Now we can consider each byte of \\( \quad 0011 \ n_{i} \quad \\) where \\(i \\) represents some \\(i^{th}\\) bit from the LSB side:

$$ B_i \quad = \quad 0011 \ n_i \quad = \quad 3 << 4 + n_i \quad = \quad 48 + n_i $$

Now rewriting \\(k\\) we have:

$$ k= B_{25} \quad B_{24} \quad B_{23} \quad .... \quad B_{2} \quad B_1 \quad B_0  $$

$$ k = B_0 \quad + \quad B_1 << 2^{8*1} \quad + \quad B_2 << 2^{8*2} \quad + \quad .... \quad + \quad B_{24} << 2^{25*7} \quad + \quad B_{24} << 2^{25*8} $$

$$ \therefore k = \sum_{i=0}^{25} = B_i * 2^{8i} $$

$$ k = \sum_{i=0}^{25} = (48 + n_i) \ * \ 2^{8i} $$

$$ \therefore k = \sum_{i=0}^{25} = 48 * 2^{8i} \ + \ \sum_{i=0}^{25} n_i \ * \ 2^{8i} $$

Great, now we have an expression for the nonce `k`.
