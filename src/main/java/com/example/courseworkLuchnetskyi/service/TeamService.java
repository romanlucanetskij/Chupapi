package com.example.courseworkLuchnetskyi.service;

import com.example.courseworkLuchnetskyi.dto.TeamMatchDto;
import com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;

import java.util.List;

public interface TeamService {
    TeamResponseDto createTeam(TeamRequestDto requestDto);
    List<TeamResponseDto> getAllTeams();
    TeamResponseDto updateTeam(Long id, TeamRequestDto requestDto);
    void deleteTeam(Long id);
    List<TeamMatchDto> getMatchesForTeam(Long teamId);
}
