if v:lang =~ "utf8$" || v:lang =~ "UTF-8$"
   set fileencodings=ucs-bom,utf-8,latin1
endif

"set ai			" always set autoindenting on
"set backup		" keep a backup file
set viminfo='20,\"50	" read/write a .viminfo file, don't store more
			" than 50 lines of registers

" Only do this part when compiled with support for autocommands
if has("autocmd")
  augroup fedora
  autocmd!
  " In text files, always limit the width of text to 78 characters
  " autocmd BufRead *.txt set tw=78
  " don't write swapfile on most commonly used directories for NFS mounts or USB sticks
  autocmd BufNewFile,BufReadPre /media/*,/run/media/*,/mnt/* set directory=~/tmp,/var/tmp,/tmp
  " start with spec file template
  autocmd BufNewFile *.spec 0r /usr/share/vim/vimfiles/template.spec
  augroup END
endif

if has("cscope") && filereadable("/usr/bin/cscope")
   set csprg=/usr/bin/cscope
   set csto=0
   set cst
   set nocsverb
   " add any database in current directory
   if filereadable("cscope.out")
      cs add $PWD/cscope.out
   " else add database pointed to by environment
   elseif $CSCOPE_DB != ""
      cs add $CSCOPE_DB
   endif
   set csverb
endif

filetype plugin on

if &term=="xterm"
     set t_Co=8
     set t_Sb=[4%dm
     set t_Sf=[3%dm
endif

" Don't wake up system with blinking cursor:
" http://www.linuxpowertop.org/known.php
let &guicursor = &guicursor . ",a:blinkon0"

" »ñÈ¡µ±Ç°Ä¿Â¼
func! GetPWD()
    return substitute(getcwd(), "", "", "g")
endf

" Ìø¹ıÒ³Í·×¢ÊÍ£¬µ½Ê×ĞĞÊµ¼Ê´úÂë
func! GotoFirstEffectiveLine()
    let l:c = 0
    while l:c<line("$") && (
                \ getline(l:c) =~ '^\s*$'
                \ || synIDattr(synID(l:c, 1, 0), "name") =~ ".*Comment.*"
                \ || synIDattr(synID(l:c, 1, 0), "name") =~ ".*PreProc$"
                \ )
        let l:c = l:c+1
    endwhile
    exe "normal ".l:c."Gz\<CR>"
endf

" ·µ»Øµ±Ç°Ê±ÆÚ
func! GetDateStamp()
    return strftime('%Y-%m-%d')
endfunction

" È«Ñ¡
func! SelectAll()
    let s:current = line('.')
    exe "norm gg" . (&slm == "" ? "VG" : "gH\<C-O>G")
endfunc

" ============
" Environment
" ============
" ±£ÁôÀúÊ·¼ÇÂ¼
set history=500

" ĞĞ¿ØÖÆ
set linebreak
set nocompatible
set textwidth=80
set wrap

" ±êÇ©Ò³
set tabpagemax=9
set showtabline=2

" ¿ØÖÆÌ¨ÏìÁå
set noerrorbells
set novisualbell
set t_vb= "close visual bell

" ĞĞºÅºÍ±ê³ß
set number

" ÃüÁîĞĞÓÚ×´Ì¬ĞĞ
set ch=1
set stl=\ [File]\ %F%m%r%h%y[%{&fileformat},%{&fileencoding}]\ %w\ \ [PWD]\ %r%{GetPWD()}%h\ %=\ [Line]%l/%L\ %=\[%P]
set ls=2 " Ê¼ÖÕÏÔÊ¾×´Ì¬ĞĞ
set wildmenu "ÃüÁîĞĞ²¹È«ÒÔÔöÇ¿Ä£Ê½ÔËĞĞ

" ¶¨Òå <Leader> Îª¶ººÅ
let mapleader = ","
let maplocalleader = ","

" Search Option
set hlsearch  " Highlight search things
set magic     " Set magic on, for regular expressions
set showmatch " Show matching bracets when text indicator is over them
set mat=2     " How many tenths of a second to blink
set noincsearch
    
" ÖÆ±í·û
set tabstop=4
set expandtab
set smarttab
set shiftwidth=4
set softtabstop=4

" ×´Ì¬À¸ÏÔÊ¾Ä¿Ç°ËùÖ´ĞĞµÄÖ¸Áî
set showcmd 

" Ëõ½ø
set autoindent
set smartindent

" ×Ô¶¯ÖØĞÂ¶ÁÈë
set autoread

" ²åÈëÄ£Ê½ÏÂÊ¹ÓÃ <BS>¡¢<Del> <C-W> <C-U>
set backspace=indent,eol,start

" Éè¶¨ÔÚÈÎºÎÄ£Ê½ÏÂÊó±ê¶¼¿ÉÓÃ
set mouse=a

" ×Ô¶¯¸Ä±äµ±Ç°Ä¿Â¼
if has('netbeans_intg')
    set autochdir
endif

" ±¸·İºÍ»º´æ
set nobackup
set noswapfile

" ×Ô¶¯Íê³É
set complete=.,w,b,k,t,i
set completeopt=longest,menu

" ´úÂëÕÛµş
set foldmethod=syntax
set foldlevel=100 " Æô¶¯vimÊ±²»Òª×Ô¶¯ÕÛµş´úÂë
" =====================
" ¶àÓïÑÔ»·¾³
"    Ä¬ÈÏÎª UTF-8 ±àÂë
" =====================
if has("multi_byte")
    set encoding=utf-8
    " English messages only
    "language messages zh_CN.utf-8
    
    if has('win32')
        language english
        let &termencoding=&encoding
    endif

    set fencs=utf-8,gbk,chinese,latin1
    set formatoptions+=mM
    set nobomb " ²»Ê¹ÓÃ Unicode Ç©Ãû

    if v:lang =~? '^\(zh\)\|\(ja\)\|\(ko\)'
        set ambiwidth=double
    endif
else
    echoerr "Sorry, this version of (g)vim was not compiled with +multi_byte"
endif

" Diff Ä£Ê½µÄÊ±ºòÊó±êÍ¬²½¹ö¶¯ for Vim7.3
if has('cursorbind')
    set cursorbind
end


" =========
" AutoCmd
" =========
if has("autocmd")

    " À¨ºÅ×Ô¶¯²¹È«
    func! AutoClose()
        :inoremap ( ()<ESC>i
        :inoremap " ""<ESC>i
        :inoremap ' ''<ESC>i
        :inoremap { {}<ESC>i
        :inoremap [ []<ESC>i
        :inoremap ) <c-r>=ClosePair(')')<CR>
        :inoremap } <c-r>=ClosePair('}')<CR>
        :inoremap ] <c-r>=ClosePair(']')<CR>
    endf

    func! ClosePair(char)
        if getline('.')[col('.') - 1] == a:char
            return "\<Right>"
        else
            return a:char
        endif
    endf

    augroup vimrcEx
        au!
        autocmd FileType text setlocal textwidth=80
        autocmd BufReadPost *
                    \ if line("'\"") > 0 && line("'\"") <= line("$") |
                    \   exe "normal g`\"" |
                    \ endif
    augroup END

    " Auto close quotation marks for PHP, Javascript, etc, file
    au FileType php,javascript,lisp,rb exe AutoClose()

    " Auto Check Syntax
    " au BufWritePost,FileWritePost *.js,*.php call CheckSyntax(1)


    " ¸ø¸÷ÓïÑÔÎÄ¼şÌí¼Ó Dict
    if has('win32')
        let s:dict_dir = $VIM.'\vimfiles\dict\'
    else
        let s:dict_dir = $HOME."/.vim/dict/"
    endif
    let s:dict_dir = "setlocal dict+=".s:dict_dir

    "au FileType php exec s:dict_dir."php_funclist.dict"
    "au FileType css exec s:dict_dir."css.dict"
    "au FileType javascript exec s:dict_dir."javascript.dict"

    " CSS3 Óï·¨Ö§³Ö
    au BufRead,BufNewFile *.css set ft=css syntax=css3

    " ½«Ö¸¶¨ÎÄ¼şµÄ»»ĞĞ·û×ª»»³É UNIX ¸ñÊ½
    au FileType php,javascript,html,css,python,vim,vimwiki set ff=unix

    " ×Ô¶¯×î´ó»¯´°¿Ú
    if has('gui_running')
        if has("win32")
            au GUIEnter * simalt ~x
            "elseif has("unix")
            "au GUIEnter * winpos 0 0
            "set lines=999 columns=999
            
            " ¸ø Win32 ÏÂµÄ gVim ´°¿ÚÉèÖÃÍ¸Ã÷¶È
            au GUIEnter * call libcallnr("vimtweak.dll", "SetAlpha", 245)
        endif
    endif
endif


" =========
" Í¼ĞÎ½çÃæ
" =========
if has('gui_running')
    " Ö»ÏÔÊ¾²Ëµ¥
    set guioptions=mcr

    " ¸ßÁÁ¹â±êËùÔÚµÄĞĞ
    if has("win32")
        " Windows ¼æÈİÅäÖÃ
        source $VIMRUNTIME/mswin.vim
        
        " ×ÖÌåÅäÖÃ
        exec 'set guifont='.iconv('Consolas', &enc, 'gbk').':h12:cANSI'
    endif

    " Under Linux/Unix etc.
    if has("unix") && !has('gui_macvim')
        set guifont=Courier\ 13
    endif

    " Under the Mac(MacVim)
    if has("mac") || has("gui_macvim")
        if has("gui_macvim")
            " MacVim ÏÂµÄ×ÖÌåÅäÖÃ
            set guifont=Courier_New:h14
            set guifontwide=YouYuan:h14

            " °ëÍ¸Ã÷ºÍ´°¿Ú´óĞ¡
            set transparency=2
            set lines=200 columns=120

            " Ê¹ÓÃ MacVim Ô­ÉúµÄÈ«ÆÁÄ»¹¦ÄÜ
            let s:lines=&lines
            let s:columns=&columns

            func! FullScreenEnter()
                set lines=999 columns=999
                set fu
            endf

            func! FullScreenLeave()
                let &lines=s:lines
                let &columns=s:columns
                set nofu
            endf

            func! FullScreenToggle()
                if &fullscreen
                    call FullScreenLeave()
                else
                    call FullScreenEnter()
                endif
            endf

            set guioptions+=e
            " Mac ÏÂ£¬°´ <Leader>ff ÇĞ»»È«ÆÁ
            nmap <f11> :call FullScreenToggle()<cr>
            nmap <Leader>ff  :call FullScreenToggle()<cr>

            " I like TCSH :^)
            set shell=/bin/tcsh

            " Set input method off
            set imdisable

            " Set QuickTemplatePath
            let g:QuickTemplatePath = $HOME.'/.vim/templates/'

            " Èç¹ûÎª¿ÕÎÄ¼ş£¬Ôò×Ô¶¯ÉèÖÃµ±Ç°Ä¿Â¼Îª×ÀÃæ
            lcd ~/Desktop/
        endif
    endif
endif

" =============
" Key Shortcut
" =============
nmap <C-o>   :tabnew<cr>
nmap <C-p>   :tabprevious<cr>
nmap <C-n>   :tabnext<cr>
nmap <C-w>   :tabclose<cr>
" nnoremap <silent> <F8> :TlistToggle<CR>

" ²åÈëÄ£Ê½°´ F4 ²åÈëµ±Ç°Ê±¼ä
" imap <f4> <C-r>=GetDateStamp()<cr>

" on Windows, default charset is gbk
if has("win32")
    let g:fontsize#encoding = "cp936"
endif

" =============
" Color Scheme
" =============
if has('syntax')
    colorscheme desert

    " Ä¬ÈÏ±à¼­Æ÷ÅäÉ«
    au BufNewFile,BufRead,BufEnter,WinEnter * colo  desert

    " ¸÷²»Í¬ÀàĞÍµÄÎÄ¼şÅäÉ«²»Í¬
    au BufNewFile,BufRead,BufEnter,WinEnter *.wiki colo void

    " ±£Ö¤Óï·¨¸ßÁÁ
    syntax on
endif

" ²å¼ş¿ì½İ¼ü
" nmap <C-d> :NERDTree<cr>
