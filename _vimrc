" File: _vimrc
" Author: Semtember<xie.tianbao44@gmail.com>
" Description: Semtember personal vim config file.
" Last Modified:  2012-05-16
" Blog: http://www.jia-210.com/
" Since: 2012-5-16


" 获取当前目录
func! GetPWD()
    return substitute(getcwd(), "", "", "g")
endf

" 跳过页头注释，到首行实际代码
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

" 返回当前时期
func! GetDateStamp()
    return strftime('%Y-%m-%d')
endfunction

" 全选
func! SelectAll()
    let s:current = line('.')
    exe "norm gg" . (&slm == "" ? "VG" : "gH\<C-O>G")
endfunc

" From an idea by Michael Naumann
func! VisualSearch(direction) range
    let l:saved_reg = @"
    execute "normal! vgvy"

    let l:pattern = escape(@", '\\/.*$^~[]')
    let l:pattern = substitute(l:pattern, "\n$", "", "")

    if a:direction == 'b'
        execute "normal ?" . l:pattern . "^M"
    elseif a:direction == 'gv'
        call CmdLine("vimgrep " . '/'. l:pattern . '/' . ' **/*.')
    elseif a:direction == 'f'
        execute "normal /" . l:pattern . "^M"
    endif

    let @/ = l:pattern
    let @" = l:saved_reg
endfunc

" ============
" Environment
" ============
" 保留历史记录
set history=500

" 行控制
set linebreak
set nocompatible
set textwidth=80
set wrap

" 标签页
set tabpagemax=9
set showtabline=2

" 控制台响铃
set noerrorbells
set novisualbell
set t_vb= "close visual bell

" 行号和标尺
set number
set ruler
set rulerformat=%15(%c%V\ %p%%%)

" 命令行于状态行
set ch=1
set stl=\ [File]\ %F%m%r%h%y[%{&fileformat},%{&fileencoding}]\ %w\ \ [PWD]\ %r%{GetPWD()}%h\ %=\ [Line]%l/%L\ %=\[%P]
set ls=2 " 始终显示状态行
set wildmenu "命令行补全以增强模式运行

" 定义 <Leader> 为逗号
let mapleader = ","
let maplocalleader = ","

" Search Option
set hlsearch  " Highlight search things
set magic     " Set magic on, for regular expressions
set showmatch " Show matching bracets when text indicator is over them
set mat=2     " How many tenths of a second to blink
set noincsearch
    
" 制表符
set tabstop=4
set expandtab
set smarttab
set shiftwidth=4
set softtabstop=4

" 状态栏显示目前所执行的指令
set showcmd 

" 缩进
set autoindent
set smartindent

" 自动重新读入
set autoread

" 插入模式下使用 <BS>、<Del> <C-W> <C-U>
set backspace=indent,eol,start

" 设定在任何模式下鼠标都可用
set mouse=a

" 自动改变当前目录
if has('netbeans_intg')
    set autochdir
endif

" 备份和缓存
set nobackup
set noswapfile

" 自动完成
set complete=.,w,b,k,t,i
set completeopt=longest,menu

" 代码折叠
set foldmethod=syntax
set foldlevel=100 " 启动vim时不要自动折叠代码
" =====================
" 多语言环境
"    默认为 UTF-8 编码
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
    set nobomb " 不使用 Unicode 签名

    if v:lang =~? '^\(zh\)\|\(ja\)\|\(ko\)'
        set ambiwidth=double
    endif
else
    echoerr "Sorry, this version of (g)vim was not compiled with +multi_byte"
endif

" 永久撤销，Vim7.3 新特性
if has('persistent_undo')
    set undofile

    " 设置撤销文件的存放的目录
    if has("unix")
        set undodir=/tmp/,~/tmp,~/Temp
    else
        set undodir=d:/temp/
    endif
    set undolevels=1000
    set undoreload=10000
endif

" Diff 模式的时候鼠标同步滚动 for Vim7.3
if has('cursorbind')
    set cursorbind
end


" =========
" AutoCmd
" =========
if has("autocmd")

    " 括号自动补全
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
    au FileType php,javascript,lisp exe AutoClose()

    " Auto Check Syntax
    " au BufWritePost,FileWritePost *.js,*.php call CheckSyntax(1)


    " 给各语言文件添加 Dict
    if has('win32')
        let s:dict_dir = $VIM.'\vimfiles\dict\'
    else
        let s:dict_dir = $HOME."/.vim/dict/"
    endif
    let s:dict_dir = "setlocal dict+=".s:dict_dir

    "au FileType php exec s:dict_dir."php_funclist.dict"
    "au FileType css exec s:dict_dir."css.dict"
    "au FileType javascript exec s:dict_dir."javascript.dict"

    " CSS3 语法支持
    au BufRead,BufNewFile *.css set ft=css syntax=css3

    " 将指定文件的换行符转换成 UNIX 格式
    au FileType php,javascript,html,css,python,vim,vimwiki set ff=unix

    " 自动最大化窗口
    if has('gui_running')
        if has("win32")
            au GUIEnter * simalt ~x
            "elseif has("unix")
            "au GUIEnter * winpos 0 0
            "set lines=999 columns=999
            
            " 给 Win32 下的 gVim 窗口设置透明度
            au GUIEnter * call libcallnr("vimtweak.dll", "SetAlpha", 245)
        endif
    endif
endif


" =========
" 图形界面
" =========
if has('gui_running')
    " 只显示菜单
    set guioptions=mcr

    " 高亮光标所在的行
    set cursorline

    if has("win32")
        " Windows 兼容配置
        source $VIMRUNTIME/mswin.vim
        
        " 字体配置
        exec 'set guifont='.iconv('Consolas', &enc, 'gbk').':h12:cANSI'
    endif

    " Under Linux/Unix etc.
    if has("unix") && !has('gui_macvim')
        set guifont=Courier\ 10\ Pitch\ 11
    endif

    " Under the Mac(MacVim)
    if has("mac") || has("gui_macvim")
        if has("gui_macvim")
            " MacVim 下的字体配置
            set guifont=Courier_New:h14
            set guifontwide=YouYuan:h14

            " 半透明和窗口大小
            set transparency=2
            set lines=200 columns=120

            " 使用 MacVim 原生的全屏幕功能
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
            " Mac 下，按 <Leader>ff 切换全屏
            nmap <f11> :call FullScreenToggle()<cr>
            nmap <Leader>ff  :call FullScreenToggle()<cr>

            " I like TCSH :^)
            set shell=/bin/tcsh

            " Set input method off
            set imdisable

            " Set QuickTemplatePath
            let g:QuickTemplatePath = $HOME.'/.vim/templates/'

            " 如果为空文件，则自动设置当前目录为桌面
            lcd ~/Desktop/
        endif
    endif
endif

" =============
" Key Shortcut
" =============
nmap <C-o>   :tabnew<cr>
nmap <C-p>   :tabprevious<cr>
"nmap <C-n>   :tabnext<cr>
nmap <C-k>   :tabclose<cr>
nmap <C-Tab> :tabnext<cr> 
nnoremap <silent> <F8> :TlistToggle<CR>

" 插入模式按 F4 插入当前时间
 imap <f4> <C-r>=GetDateStamp()<cr>

" on Windows, default charset is gbk
if has("win32")
    let g:fontsize#encoding = "cp936"
endif

" =============
" Color Scheme
" =============
if has('syntax')
    colorscheme desert

    " 默认编辑器配色
    au BufNewFile,BufRead,BufEnter,WinEnter * colo  desert

    " 各不同类型的文件配色不同
    au BufNewFile,BufRead,BufEnter,WinEnter *.wiki colo void

    " 保证语法高亮
    syntax on
endif




" 插件快捷键
nmap <C-d> :NERDTree<cr>

set diffexpr=MyDiff()
function MyDiff()
  let opt = '-a --binary '
  if &diffopt =~ 'icase' | let opt = opt . '-i ' | endif
  if &diffopt =~ 'iwhite' | let opt = opt . '-b ' | endif
  let arg1 = v:fname_in
  if arg1 =~ ' ' | let arg1 = '"' . arg1 . '"' | endif
  let arg2 = v:fname_new
  if arg2 =~ ' ' | let arg2 = '"' . arg2 . '"' | endif
  let arg3 = v:fname_out
  if arg3 =~ ' ' | let arg3 = '"' . arg3 . '"' | endif
  let eq = ''
  if $VIMRUNTIME =~ ' '
    if &sh =~ '\<cmd'
      let cmd = '""' . $VIMRUNTIME . '\diff"'
      let eq = '"'
    else
      let cmd = substitute($VIMRUNTIME, ' ', '" ', '') . '\diff"'
    endif
  else
    let cmd = $VIMRUNTIME . '\diff'
  endif
  silent execute '!' . cmd . ' ' . opt . arg1 . ' ' . arg2 . ' > ' . arg3 . eq
endfunction



" for taglist
let g:Tlist_Use_Right_Window = 1
let g:Tlist_WinWidth = 25

" for sniMate
" let g:snippets_dir = "E:\Program Files (x86)\Vim\vimfiles\snippets"


