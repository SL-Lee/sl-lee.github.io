---
created: 2026-01-11T00:11:38
---
# Why I Learned Typst

I came across [Typst](https://typst.app) a while ago, and I would like to share what led me to try it.

## Microsoft Word can't save math right

I was working on a math cheat sheet in Microsoft Word when I encountered a rather peculiar bug with how Microsoft Word messes up math expressions for functions like $sin$ and $log$ that was inputted as LaTeX expressions and then converted to the "Professional" format. This is happening in the _latest_ version (2511) of Word, by the way, not some ancient version (you can follow along in reproducing the bug if you want 😊).

Create a _new_ Microsoft Word document and insert a new equation (`Alt`+`=`) and input a LaTeX expression for `\sin{x}`.

![[images/msword-inputting-latex-eqn.png]]

Use the equation toolbar to convert the current equation to "Professional".

![[images/msword-converting-latex-eqn-to-professional.png]]

The resulting equation looks okay, right?

![[images/msword-converted-professional-latex-eqn.png]]

Now, here's the fun part. You simply _save_ the document, then _reopen_ it. Nothing should have changed, right? Of course not, it's Microsoft, what did you expect:

![[images/msword-converted-professional-latex-eqn-saved-reopened.png]]

Somehow, Microsoft Word has saved the equation as _text_. If you convert this equation to "linear" now, you expect it to show `\sin{x}`, but you get `sin{x}` instead. The backslash got lost in the void, somehow.

![[images/msword-converted-linear-latex-eqn-saved-reopened.png]]

So far, the only workaround I have tried is to manually input an equation by clicking around the toolbar and hunting for the various functions/symbols, all the while making sure your cursor is at _juuuust_ the right position. Just amazing.

So, what does a reasonable person like me (which I _think_ I am, to some extent) do in this scenario? Ignore the bug (since it is just a stylistic bug anyway)? Swear off inputting equations in LaTeX in Microsoft Word forever and insert equations by clicking? Send a feedback report to Micro~~slop~~ soft and _hope_ they actually read the report and that the fix, if they are bothered to create one using AI, actually fixes the problem? Nope, you go and learn an entirely new typesetting system, that's what.

## Typst is a delight

Jokes aside, I heard of Typst from my news feed a while ago (back when version 0.14.0 was released in October 2025). I never got a chance to try it, so I figured why not give it a spin. It is positioned as the "modern" alternative of LaTeX, being easy to use (no need for backslashes `\` to be littered everywhere) and being actually programmable (instead of the weird and inconsistent macro system LaTeX uses).

It combines (some) elements inspired from Markdown with some unique concepts of its own.

For examples of the former, _italic text_ is achieved by surrounding text with a single underscore, and _bold text_ is achieved by surrounding text with a **single** asterisk. Inline code is also achieved by surrounding text with a single backtick, and you can have code blocks with triple backticks.

For the latter, it differentiates between three "syntactical modes": markup, code, and math. The default mode is markup mode, but you can switch to code and math with `#` and `$`, respectively. For example, you can call a function in markup mode with `#my-function()`, but in code mode, you can call the same function by omitting the leading `#`; math equations can be inputted like `$x = 5$`.

It is obviously impractical for me to recite the entire Typst tutorial here, so I would recommend going through the [tutorial](https://typst.app/docs/tutorial/) or [reference](https://typst.app/docs/reference/syntax/) if you're interested to learn more.

But even with rudimentary knowledge, I was able to easily re-create my math cheat sheet in Typst due to how easy it was to input equations in Typst. The equivalent to LaTeX's `\sin{x}` in Typst is... wait for it:

```typ
$sin x$
```

Which gets rendered as:

![[images/typst-sin-x-rendered.png]]

That's because `sin` (and other functions and symbols like `cos`, `tan`, `pi`, etc.) are predefined in Typst's math mode, so no backslash or any special characters are needed to access it. Single letters are treated as variables, so it gets italicized. If, for some reason, you wanted to recreate the Microsoft Word atrocity above, you would have to deliberately space out the letters, i.e.: `$s i n x$`.

But don't be fooled by this simplicity! The power Typst brings cannot be understated. For example, despite being a newbie, I was in awe of how simple and intuitive it was to programmatically generate documents (example from [here](https://github.com/fenjalien/obsidian-typst)):

```typ
= Fibonacci sequence
The Fibonacci sequence is defined through the
_recurrence relation_ $F_n = F_(n-1) + F_(n-2)$.
It can also be expressed in closed form:

$ F_n = floor(1 / sqrt(5) phi.alt^n), quad
  phi.alt = (1 + sqrt(5)) / 2 $

#let count = 10
#let nums = range(1, count + 1)
#let fib(n) = (
  if n <= 2 { 1 }
  else { fib(n - 1) + fib(n - 2) }
)

The first #count numbers of the sequence are:

#align(center, table(
  columns: count,
  ..nums.map(n => $F_#n$),
  ..nums.map(n => str(fib(n))),
))
```
![[images/typst-fibonacci-sequence-generated-doc-rendered.png]]

So for people who are sick of inputting equations in Microsoft Word, sick of LaTeX (hey, Typst has a [guide for LaTeX users](https://typst.app/docs/guides/for-latex-users/) too!), or just simply have some free time and wants to dabble with something cool, I would recommend trying or at least checking out Typst.

The language itself is [open-source](https://github.com/typst/typst), has an [online collaborative editor](https://typst.app/play/), and for people like me who wants to run it locally, there is an amazing community extension called [Tinymist Typst](https://marketplace.visualstudio.com/items?itemName=myriad-dreamin.tinymist) for Visual Studio Code (did I mention it supports live-preview too??).
