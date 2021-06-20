<div class="colorscripter-code" style="color: #f0f0f0; font-family: Consolas, 'Liberation Mono', Menlo, Courier, monospace !important; position: relative !important; overflow: auto;">
<table class="colorscripter-code-table" style="margin: 0; padding: 0; border: none; background-color: #272727; border-radius: 4px;" cellspacing="0" cellpadding="0">
<tbody>
<tr>
<td style="padding: 6px; border-right: 2px solid #4f4f4f;">
<div style="margin: 0; padding: 0; word-break: normal; text-align: right; color: #aaa; font-family: Consolas, 'Liberation Mono', Menlo, Courier, monospace !important; line-height: 130%;">
<div style="line-height: 130%;">1</div>
<div style="line-height: 130%;">2</div>
<div style="line-height: 130%;">3</div>
<div style="line-height: 130%;">4</div>
<div style="line-height: 130%;">5</div>
<div style="line-height: 130%;">6</div>
<div style="line-height: 130%;">7</div>
<div style="line-height: 130%;">8</div>
<div style="line-height: 130%;">9</div>
<div style="line-height: 130%;">10</div>
<div style="line-height: 130%;">11</div>
<div style="line-height: 130%;">12</div>
<div style="line-height: 130%;">13</div>
<div style="line-height: 130%;">14</div>
<div style="line-height: 130%;">15</div>
<div style="line-height: 130%;">16</div>
<div style="line-height: 130%;">17</div>
<div style="line-height: 130%;">18</div>
<div style="line-height: 130%;">19</div>
<div style="line-height: 130%;">20</div>
<div style="line-height: 130%;">21</div>
</div>
</td>
<td style="padding: 6px 0; text-align: left;">
<div style="margin: 0; padding: 0; color: #f0f0f0; font-family: Consolas, 'Liberation Mono', Menlo, Courier, monospace !important; line-height: 130%;">
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">flag&nbsp;<span style="color: #ff3399;">=</span>&nbsp;[<span style="color: #c10aff;">122</span>,&nbsp;<span style="color: #c10aff;">104</span>,&nbsp;<span style="color: #c10aff;">51</span>,&nbsp;<span style="color: #c10aff;">114</span>,&nbsp;<span style="color: #c10aff;">48</span>,&nbsp;<span style="color: #c10aff;">123</span>,&nbsp;<span style="color: #c10aff;">125</span>]</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;"><span style="color: #999999;">#z&nbsp;&nbsp;&nbsp;h&nbsp;&nbsp;&nbsp;3&nbsp;&nbsp;r&nbsp;&nbsp;&nbsp;0&nbsp;&nbsp;{&nbsp;&nbsp;&nbsp;}&nbsp;&nbsp;&nbsp;&nbsp;</span></div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;"><span style="color: #999999;">#122&nbsp;104&nbsp;51&nbsp;114&nbsp;48&nbsp;123&nbsp;125</span></div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;"><span style="color: #ff3399;">def</span>&nbsp;nk2n(nk):</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;l&nbsp;<span style="color: #ff3399;">=</span>&nbsp;<span style="color: #4be6fa;">len</span>(nk)</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #ff3399;">if</span>&nbsp;l<span style="color: #ff3399;">=</span><span style="color: #ff3399;">=</span><span style="color: #c10aff;">1</span>:</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #4be6fa;">print</span>(<span style="color: #ffd500;">"l&nbsp;==&nbsp;1&nbsp;:&nbsp;"</span>,&nbsp;<span style="color: #ffd500;">"returning:"</span>,&nbsp;nk)</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #ff3399;">return</span>&nbsp;nk[<span style="color: #c10aff;">0</span>]</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #ff3399;">elif</span>&nbsp;l<span style="color: #ff3399;">=</span><span style="color: #ff3399;">=</span><span style="color: #c10aff;">2</span>:</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #999999;">#print("l&nbsp;==2:",&nbsp;nk)</span></div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;i,j&nbsp;<span style="color: #ff3399;">=</span>&nbsp;nk</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #4be6fa;">print</span>(<span style="color: #ffd500;">"l&nbsp;==&nbsp;2&nbsp;:"</span>,&nbsp;nk,&nbsp;<span style="color: #ffd500;">"returning:"</span>,&nbsp;(&nbsp;(i<span style="color: #ff3399;">+</span>j)&nbsp;<span style="color: #ff3399;">*</span>&nbsp;(i<span style="color: #ff3399;">+</span>j<span style="color: #ff3399;">+</span><span style="color: #c10aff;">1</span>)&nbsp;)&nbsp;<span style="color: #ff3399;">/</span><span style="color: #ff3399;">/</span>&nbsp;<span style="color: #c10aff;">2</span>&nbsp;<span style="color: #ff3399;">+</span>&nbsp;j)</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #ff3399;">return</span>&nbsp;(&nbsp;(i<span style="color: #ff3399;">+</span>j)&nbsp;<span style="color: #ff3399;">*</span>&nbsp;(i<span style="color: #ff3399;">+</span>j<span style="color: #ff3399;">+</span><span style="color: #c10aff;">1</span>)&nbsp;)&nbsp;<span style="color: #ff3399;">/</span><span style="color: #ff3399;">/</span>&nbsp;<span style="color: #c10aff;">2</span>&nbsp;<span style="color: #ff3399;">+</span>&nbsp;j</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #999999;">#print("nk2n[:",&nbsp;l-l//2,&nbsp;"]&nbsp;nk2n[",&nbsp;l-l//2,&nbsp;":]")</span></div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #4be6fa;">print</span>(<span style="color: #ffd500;">"First&nbsp;half&nbsp;:&nbsp;"</span>,&nbsp;nk[:l<span style="color: #ff3399;">-</span>l<span style="color: #ff3399;">/</span><span style="color: #ff3399;">/</span><span style="color: #c10aff;">2</span>],&nbsp;<span style="color: #ffd500;">"Second&nbsp;half&nbsp;:"</span>,&nbsp;nk[&nbsp;l<span style="color: #ff3399;">-</span>l<span style="color: #ff3399;">/</span><span style="color: #ff3399;">/</span><span style="color: #c10aff;">2</span>:])</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;">&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #ff3399;">return</span>&nbsp;nk2n(&nbsp;&nbsp;[&nbsp;nk2n(nk&nbsp;[:l<span style="color: #ff3399;">-</span>l<span style="color: #ff3399;">/</span><span style="color: #ff3399;">/</span><span style="color: #c10aff;">2</span>]&nbsp;)&nbsp;,&nbsp;nk2n(nk[&nbsp;l<span style="color: #ff3399;">-</span>l<span style="color: #ff3399;">/</span><span style="color: #ff3399;">/</span><span style="color: #c10aff;">2</span>:]&nbsp;)&nbsp;]&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;)</div>
<div style="padding: 0 6px; white-space: pre; line-height: 130%;"><span style="color: #4be6fa;">print</span>(<span style="color: #ffd500;">"The&nbsp;encrypted&nbsp;flag&nbsp;is&nbsp;:&nbsp;"</span>,&nbsp;nk2n(flag))</div>
</div>
</td>
<td style="vertical-align: bottom; padding: 0 2px 4px 0;">&nbsp;</td>
</tr>
</tbody>
</table>
</div>
