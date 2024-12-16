---
layout: post
title: "Windows/Usernames AD formatter"
subtitle: "Bash tool to change usernames to match active directory format"
date: 2024-08-22 23:45:13
author: "xtromera"
background: '/img/bg-arsenal.jpg'
excerpt: "Bash tool to change usernames to match active directory format."

---


# Introduction

Active Directory (AD) environments often require usernames to follow specific formats, which can make generating and managing usernames a bit cumbersome. In this post, we’ll introduce a tool designed to take a list of usernames and automatically format them to match common AD conventions. This tool will save time, eliminate human errors, and make it easy to integrate lists into an AD environment.

The tool’s source code is adapted from [this repository](https://github.com/PinkDraconian/CTF-bash-tools), which features a collection of bash tools useful for various CTF and penetration testing scenarios. 

## Features

- Takes a list of usernames and generates formatted outputs to match different AD conventions.
- Supports common AD formats such as:
  - `first.last`
  - `firstl` (first name + last initial)
  - `f_last` (first initial + last name)
- Handles duplicates by appending numeric values if needed.

## Usage

1. **Input**: Provide a list of usernames, each on a new line, as input.
2. **Formatting**: The tool will process the usernames and format them to match one of the common AD conventions listed above.
3. **Output**: The formatted usernames can be saved to a file or directly used for further AD operations.

### Example

Consider the following list of usernames:

```
John Doe
Jane Smith
Bob Johnson
Alice Brown
```

After running the tool, you might get outputs like:

- `john.doe`
- `jane.smith`
- `b.johnson`
- `alice.b`

## Code Overview

```bash
#!/bin/bash

#
# Gets a list with `firstname lastname` and formats them into the following:
# 	NameSurname, Name.Surname, NamSur (3letters of each), Nam.Sur, NSurname, N.Surname, SurnameName, Surname.Name, SurnameN, Surname.N,
#

if [[ $ == "-h" || $# != 1 ]]; then
	echo "Usage: ctf-wordlist-names names-file"
	exit
fi

if [ -f formatted_name_wordlist.txt ]; then
    echo "[!] formatted_name_wordlist.txt file already exist."
    exit 1
fi

cat $1 | while read line; do
	firstname=$(echo $line | cut -d ' ' -f1 | tr '[:upper:]' '[:lower:]')
	lastname=$(echo $line | cut -d ' ' -f2 | tr '[:upper:]' '[:lower:]')
	echo "$firstname.$lastname
$(echo $firstname | cut -c1).$lastname
$(echo $firstname | cut -c1)-$lastname
$firstname$lastname
$firstname-$lastname
$(echo $firstname | cut -c1-3)$(echo $lastname | cut -c1-3)
$(echo $firstname | cut -c1-3).$(echo $lastname | cut -c1-3)
$(echo $firstname | cut -c1)$lastname
$lastname$firstname
$lastname-$firstname
$lastname.$firstname
$lastname$(echo $firstname | cut -c1)
$lastname-$(echo $firstname | cut -c1)
$lastname.$(echo $firstname | cut -c1)" >> formatted_name_wordlist.txt
done
```

